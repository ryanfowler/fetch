#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const APP_THREAD_STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() {
    let code = std::thread::Builder::new()
        .name("fetch-main".to_string())
        .stack_size(APP_THREAD_STACK_SIZE)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");
            runtime.block_on(fetch::app::main_entry())
        })
        .expect("failed to spawn fetch main thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    std::process::exit(code);
}
