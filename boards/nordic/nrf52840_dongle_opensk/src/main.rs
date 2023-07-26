//! Tock kernel for the Nordic Semiconductor nRF52840 dongle.
//!
//! It is based on nRF52840 SoC (Cortex M4 core with a BLE transceiver) with
//! many exported I/O and peripherals.

#![no_std]
// Disable this attribute when documenting, as a workaround for
// https://github.com/rust-lang/rust/issues/62184.
#![cfg_attr(not(doc), no_main)]
#![deny(missing_docs)]

use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
use kernel::component::Component;
use kernel::deferred_call::DeferredCallClient;
use kernel::hil::led::LedLow;
use kernel::hil::time::Counter;
use kernel::platform::{KernelResources, SyscallDriverLookup, SyscallFilter};
use kernel::scheduler::round_robin::RoundRobinSched;
#[allow(unused_imports)]
use kernel::{capabilities, create_capability, debug, debug_gpio, debug_verbose, static_init};
use kernel::{StorageLocation, StorageType};
use nrf52840::gpio::Pin;
use nrf52840::interrupt_service::Nrf52840DefaultPeripherals;
use nrf52_components::{self, UartChannel, UartPins};

// The nRF52840 Dongle LEDs
const LED1_PIN: Pin = Pin::P0_06;
const LED2_R_PIN: Pin = Pin::P0_08;
const LED2_G_PIN: Pin = Pin::P1_09;
const LED2_B_PIN: Pin = Pin::P0_12;

// The nRF52840 Dongle button
const BUTTON_PIN: Pin = Pin::P1_06;
const BUTTON_RST_PIN: Pin = Pin::P0_18;

const UART_RTS: Option<Pin> = Some(Pin::P0_13);
const UART_TXD: Pin = Pin::P0_15;
const UART_CTS: Option<Pin> = Some(Pin::P0_17);
const UART_RXD: Pin = Pin::P0_20;

// SPI pins not currently in use, but left here for convenience
const _SPI_MOSI: Pin = Pin::P1_01;
const _SPI_MISO: Pin = Pin::P1_02;
const _SPI_CLK: Pin = Pin::P1_04;

/// UART Writer
pub mod io;

const VENDOR_ID: u16 = 0x1915; // Nordic Semiconductor
const PRODUCT_ID: u16 = 0x521f; // nRF52840 Dongle (PCA10059)
static STRINGS: &'static [&'static str] = &[
    // Manufacturer
    "Nordic Semiconductor ASA",
    // Product
    "OpenSK",
    // Serial number
    "v1.0",
];

// State for loading and holding applications.
// How should the kernel respond when a process faults.
const FAULT_RESPONSE: kernel::process::PanicFaultPolicy = kernel::process::PanicFaultPolicy {};

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 8;

static mut PROCESSES: [Option<&'static dyn kernel::process::Process>; NUM_PROCS] =
    [None; NUM_PROCS];

static mut STORAGE_LOCATIONS: [StorageLocation; 2] = [
    // We implement NUM_PAGES = 20 as 16 + 4 to satisfy the MPU.
    StorageLocation {
        address: 0xC0000,
        size: 0x10000, // 16 pages
        storage_type: StorageType::Store,
    },
    StorageLocation {
        address: 0xD0000,
        size: 0x4000, // 4 pages
        storage_type: StorageType::Store,
    },
];

// Static reference to chip for panic dumps
static mut CHIP: Option<&'static nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>> = None;
// Static reference to process printer for panic dumps
static mut PROCESS_PRINTER: Option<&'static kernel::process::ProcessPrinterText> = None;

/// Flash buffer for the custom nvmc driver
static mut APP_FLASH_BUFFER: [u8; 0x1000] = [0; 0x1000];

/// Dummy buffer that causes the linker to reserve enough space for the stack.
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x1000] = [0; 0x1000];

// Function for the process console to use to reboot the board
fn reset() -> ! {
    unsafe {
        cortexm4::scb::reset();
    }
    loop {
        cortexm4::support::nop();
    }
}

/// Supported drivers by the platform
pub struct Platform {
    button: &'static capsules_core::button::Button<'static, nrf52840::gpio::GPIOPin<'static>>,
    pconsole: &'static capsules_core::process_console::ProcessConsole<
        'static,
        { capsules_core::process_console::DEFAULT_COMMAND_HISTORY_LEN },
        VirtualMuxAlarm<'static, nrf52840::rtc::Rtc<'static>>,
        components::process_console::Capability,
    >,
    console: &'static capsules_core::console::Console<'static>,
    gpio: &'static capsules_core::gpio::GPIO<'static, nrf52840::gpio::GPIOPin<'static>>,
    led: &'static capsules_core::led::LedDriver<
        'static,
        LedLow<'static, nrf52840::gpio::GPIOPin<'static>>,
        4,
    >,
    rng: &'static capsules_core::rng::RngDriver<'static>,
    ipc: kernel::ipc::IPC<{ NUM_PROCS as u8 }>,
    analog_comparator: &'static capsules_extra::analog_comparator::AnalogComparator<
        'static,
        nrf52840::acomp::Comparator<'static>,
    >,
    alarm: &'static capsules_core::alarm::AlarmDriver<
        'static,
        capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm<'static, nrf52840::rtc::Rtc<'static>>,
    >,
    scheduler: &'static RoundRobinSched<'static>,
    systick: cortexm4::systick::SysTick,
    nvmc: &'static nrf52840::nvmc::SyscallDriver,
    usb: &'static capsules_extra::usb::usb_ctap::CtapUsbSyscallDriver<
        'static,
        'static,
        nrf52840::usbd::Usbd<'static>,
    >,
}

impl SyscallDriverLookup for Platform {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_core::console::DRIVER_NUM => f(Some(self.console)),
            capsules_core::gpio::DRIVER_NUM => f(Some(self.gpio)),
            capsules_core::alarm::DRIVER_NUM => f(Some(self.alarm)),
            capsules_core::led::DRIVER_NUM => f(Some(self.led)),
            capsules_core::button::DRIVER_NUM => f(Some(self.button)),
            capsules_core::rng::DRIVER_NUM => f(Some(self.rng)),
            capsules_extra::analog_comparator::DRIVER_NUM => f(Some(self.analog_comparator)),
            nrf52840::nvmc::DRIVER_NUM => f(Some(self.nvmc)),
            capsules_extra::usb::usb_ctap::DRIVER_NUM => f(Some(self.usb)),
            kernel::ipc::DRIVER_NUM => f(Some(&self.ipc)),
            _ => f(None),
        }
    }
}

impl SyscallFilter for Platform {
    fn filter_syscall(
        &self,
        process: &dyn kernel::process::Process,
        syscall: &kernel::syscall::Syscall,
    ) -> Result<(), kernel::errorcode::ErrorCode> {
        use kernel::syscall::Syscall;
        match *syscall {
            Syscall::Command {
                driver_number: nrf52840::nvmc::DRIVER_NUM,
                subdriver_number: cmd,
                arg0: ptr,
                arg1: len,
            } if (cmd == 2 || cmd == 3) && !process.fits_in_storage_location(ptr, len) => {
                Err(kernel::ErrorCode::INVAL)
            }
            _ => Ok(()),
        }
    }
}

impl KernelResources<nrf52840::chip::NRF52<'static, Nrf52840DefaultPeripherals<'static>>>
    for Platform
{
    type SyscallDriverLookup = Self;
    type SyscallFilter = Self;
    type ProcessFault = ();
    type CredentialsCheckingPolicy = ();
    type Scheduler = RoundRobinSched<'static>;
    type SchedulerTimer = cortexm4::systick::SysTick;
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        &self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &self
    }
    fn process_fault(&self) -> &Self::ProcessFault {
        &()
    }
    fn credentials_checking_policy(&self) -> &'static Self::CredentialsCheckingPolicy {
        &()
    }
    fn scheduler(&self) -> &Self::Scheduler {
        self.scheduler
    }
    fn scheduler_timer(&self) -> &Self::SchedulerTimer {
        &self.systick
    }
    fn watchdog(&self) -> &Self::WatchDog {
        &()
    }
    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback {
        &()
    }
}

/// This is in a separate, inline(never) function so that its stack frame is
/// removed when this function returns. Otherwise, the stack space used for
/// these static_inits is wasted.
#[inline(never)]
unsafe fn get_peripherals() -> &'static mut Nrf52840DefaultPeripherals<'static> {
    // Initialize chip peripheral drivers
    let nrf52840_peripherals = static_init!(
        Nrf52840DefaultPeripherals,
        Nrf52840DefaultPeripherals::new()
    );

    nrf52840_peripherals
}

/// Main function called after RAM initialized.
#[no_mangle]
pub unsafe fn main() {
    nrf52840::init();

    let nrf52840_peripherals = get_peripherals();

    // set up circular peripheral dependencies
    nrf52840_peripherals.init();
    let base_peripherals = &nrf52840_peripherals.nrf52;

    let board_kernel = static_init!(
        kernel::Kernel,
        kernel::Kernel::new_with_storage(&PROCESSES, &STORAGE_LOCATIONS)
    );

    // GPIOs
    let gpio = components::gpio::GpioComponent::new(
        board_kernel,
        capsules_core::gpio::DRIVER_NUM,
        components::gpio_component_helper!(
            nrf52840::gpio::GPIOPin,
            // left side of the USB plug
            0 => &nrf52840_peripherals.gpio_port[Pin::P0_13],
            1 => &nrf52840_peripherals.gpio_port[Pin::P0_15],
            2 => &nrf52840_peripherals.gpio_port[Pin::P0_17],
            3 => &nrf52840_peripherals.gpio_port[Pin::P0_20],
            4 => &nrf52840_peripherals.gpio_port[Pin::P0_22],
            5 => &nrf52840_peripherals.gpio_port[Pin::P0_24],
            6 => &nrf52840_peripherals.gpio_port[Pin::P1_00],
            7 => &nrf52840_peripherals.gpio_port[Pin::P0_09],
            8 => &nrf52840_peripherals.gpio_port[Pin::P0_10],
            // right side of the USB plug
            9 => &nrf52840_peripherals.gpio_port[Pin::P0_31],
            10 => &nrf52840_peripherals.gpio_port[Pin::P0_29],
            11 => &nrf52840_peripherals.gpio_port[Pin::P0_02],
            12 => &nrf52840_peripherals.gpio_port[Pin::P1_15],
            13 => &nrf52840_peripherals.gpio_port[Pin::P1_13],
            14 => &nrf52840_peripherals.gpio_port[Pin::P1_10],
            // Below the PCB
            15 => &nrf52840_peripherals.gpio_port[Pin::P0_26],
            16 => &nrf52840_peripherals.gpio_port[Pin::P0_04],
            17 => &nrf52840_peripherals.gpio_port[Pin::P0_11],
            18 => &nrf52840_peripherals.gpio_port[Pin::P0_14],
            19 => &nrf52840_peripherals.gpio_port[Pin::P1_11],
            20 => &nrf52840_peripherals.gpio_port[Pin::P1_07],
            21 => &nrf52840_peripherals.gpio_port[Pin::P1_01],
            22 => &nrf52840_peripherals.gpio_port[Pin::P1_04],
            23 => &nrf52840_peripherals.gpio_port[Pin::P1_02]
        ),
    )
    .finalize(components::gpio_component_static!(nrf52840::gpio::GPIOPin));

    let button = components::button::ButtonComponent::new(
        board_kernel,
        capsules_core::button::DRIVER_NUM,
        components::button_component_helper!(
            nrf52840::gpio::GPIOPin,
            (
                &nrf52840_peripherals.gpio_port[BUTTON_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            )
        ),
    )
    .finalize(components::button_component_static!(
        nrf52840::gpio::GPIOPin
    ));

    let led = components::led::LedsComponent::new().finalize(components::led_component_static!(
        LedLow<'static, nrf52840::gpio::GPIOPin>,
        LedLow::new(&nrf52840_peripherals.gpio_port[LED1_PIN]),
        LedLow::new(&nrf52840_peripherals.gpio_port[LED2_R_PIN]),
        LedLow::new(&nrf52840_peripherals.gpio_port[LED2_G_PIN]),
        LedLow::new(&nrf52840_peripherals.gpio_port[LED2_B_PIN]),
    ));

    let chip = static_init!(
        nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
        nrf52840::chip::NRF52::new(nrf52840_peripherals)
    );
    CHIP = Some(chip);

    nrf52_components::startup::NrfStartupComponent::new(
        false,
        BUTTON_RST_PIN,
        nrf52840::uicr::Regulator0Output::V3_0,
        &base_peripherals.nvmc,
    )
    .finalize(());

    // Create capabilities that the board needs to call certain protected kernel
    // functions.
    let process_management_capability =
        create_capability!(capabilities::ProcessManagementCapability);
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);
    let memory_allocation_capability = create_capability!(capabilities::MemoryAllocationCapability);

    let gpio_port = &nrf52840_peripherals.gpio_port;

    // Configure kernel debug gpios as early as possible
    kernel::debug::assign_gpios(
        Some(&gpio_port[LED2_R_PIN]),
        Some(&gpio_port[LED2_G_PIN]),
        Some(&gpio_port[LED2_B_PIN]),
    );

    let rtc = &base_peripherals.rtc;
    let _ = rtc.start();
    let mux_alarm = components::alarm::AlarmMuxComponent::new(rtc)
        .finalize(components::alarm_mux_component_static!(nrf52840::rtc::Rtc));
    let alarm = components::alarm::AlarmDriverComponent::new(
        board_kernel,
        capsules_core::alarm::DRIVER_NUM,
        mux_alarm,
    )
    .finalize(components::alarm_component_static!(nrf52840::rtc::Rtc));
    let uart_channel = UartChannel::Pins(UartPins::new(UART_RTS, UART_TXD, UART_CTS, UART_RXD));
    let channel = nrf52_components::UartChannelComponent::new(
        uart_channel,
        mux_alarm,
        &base_peripherals.uarte0,
    )
    .finalize(nrf52_components::uart_channel_component_static!(
        nrf52840::rtc::Rtc
    ));

    let process_printer = components::process_printer::ProcessPrinterTextComponent::new()
        .finalize(components::process_printer_text_component_static!());
    PROCESS_PRINTER = Some(process_printer);

    // Create a shared UART channel for the console and for kernel debug.
    let uart_mux = components::console::UartMuxComponent::new(channel, 115200)
            .finalize(components::uart_mux_component_static!());

    let pconsole = components::process_console::ProcessConsoleComponent::new(
        board_kernel,
        uart_mux,
        mux_alarm,
        process_printer,
        Some(reset),
    )
    .finalize(components::process_console_component_static!(
        nrf52840::rtc::Rtc<'static>
    ));

    // Setup the console.
    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());
    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new(uart_mux)
        .finalize(components::debug_writer_component_static!());

    let rng = components::rng::RngComponent::new(
        board_kernel,
        capsules_core::rng::DRIVER_NUM,
        &base_peripherals.trng,
    )
    .finalize(components::rng_component_static!());

    // Initialize AC using AIN5 (P0.29) as VIN+ and VIN- as AIN0 (P0.02)
    // These are hardcoded pin assignments specified in the driver
    let analog_comparator = components::analog_comparator::AnalogComparatorComponent::new(
        &base_peripherals.acomp,
        components::analog_comparator_component_helper!(
            nrf52840::acomp::Channel,
            &nrf52840::acomp::CHANNEL_AC0
        ),
        board_kernel,
        capsules_extra::analog_comparator::DRIVER_NUM,
    )
    .finalize(components::analog_comparator_component_static!(
        nrf52840::acomp::Comparator
    ));

    let nvmc = static_init!(
        nrf52840::nvmc::SyscallDriver,
        nrf52840::nvmc::SyscallDriver::new(
            &base_peripherals.nvmc,
            board_kernel.create_grant(nrf52840::nvmc::DRIVER_NUM, &memory_allocation_capability),
            &mut APP_FLASH_BUFFER,
        )
    );
    nvmc.register();

    // Configure USB controller
    let usb = components::usb_ctap::UsbCtapComponent::new(
        board_kernel,
        capsules_extra::usb::usb_ctap::DRIVER_NUM,
        &nrf52840_peripherals.usbd,
        capsules_extra::usb::usbc_client::MAX_CTRL_PACKET_SIZE_NRF52840,
        VENDOR_ID,
        PRODUCT_ID,
        STRINGS,
    )
    .finalize(components::usb_ctap_component_helper!(nrf52840::usbd::Usbd));

    nrf52_components::NrfClockComponent::new(&base_peripherals.clock).finalize(());

    let scheduler = components::sched::round_robin::RoundRobinComponent::new(&PROCESSES)
        .finalize(components::round_robin_component_static!(NUM_PROCS));

    let platform = Platform {
        button,
        pconsole,
        console,
        led,
        gpio,
        rng,
        alarm,
        analog_comparator,
        nvmc,
        usb,
        ipc: kernel::ipc::IPC::new(
            board_kernel,
            kernel::ipc::DRIVER_NUM,
            &memory_allocation_capability,
        ),
        scheduler,
        systick: cortexm4::systick::SysTick::new_with_calibration(6400_0000),
    };

    let _ = platform.pconsole.start();
    debug!("Initialization complete. Entering main loop\r");
    debug!("{}", &nrf52840::ficr::FICR_INSTANCE);

    // These symbols are defined in the linker script.
    extern "C" {
        /// Beginning of the ROM region containing app images.
        static _sapps: u8;
        /// End of the ROM region containing app images.
        static _eapps: u8;
        /// Beginning of the RAM region for app memory.
        static mut _sappmem: u8;
        /// End of the RAM region for app memory.
        static _eappmem: u8;
    }

    kernel::process::load_processes(
        board_kernel,
        chip,
        core::slice::from_raw_parts(
            &_sapps as *const u8,
            &_eapps as *const u8 as usize - &_sapps as *const u8 as usize,
        ),
        core::slice::from_raw_parts_mut(
            &mut _sappmem as *mut u8,
            &_eappmem as *const u8 as usize - &_sappmem as *const u8 as usize,
        ),
        &mut PROCESSES,
        &FAULT_RESPONSE,
        &process_management_capability,
    )
    .unwrap_or_else(|err| {
        debug!("Error loading processes!");
        debug!("{:?}", err);
    });

    board_kernel.kernel_loop(&platform, chip, Some(&platform.ipc), &main_loop_capability);
}
