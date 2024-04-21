use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
    Throughput,
};
use once_cell::sync::Lazy;

static TOKIO: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

fn random(buf: sodoken::legacy::BufWrite) {
    TOKIO.block_on(async move {
        sodoken::legacy::random::bytes_buf(buf).await.unwrap();
    });
}

fn bench(c: &mut Criterion) {
    static KB: usize = 1024;

    let mut group = c.benchmark_group("random");
    // CURRENTLY we switch over to spawn_blocking above 10 * KB
    for size in [KB, 10 * KB, 11 * KB, 20 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            move |b, &size| {
                let buf = sodoken::legacy::BufWrite::new_no_lock(size);
                b.iter(move || {
                    random(black_box(buf.clone()));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
