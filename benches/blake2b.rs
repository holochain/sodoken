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

fn blake2b(hash: sodoken::legacy::BufWrite, data: sodoken::legacy::BufWrite) {
    TOKIO.block_on(async move {
        sodoken::legacy::hash::blake2b::hash(hash, data)
            .await
            .unwrap();
    });
}

fn bench(c: &mut Criterion) {
    static KB: usize = 1024;

    let mut group = c.benchmark_group("blake2b");
    // CURRENTLY we switch over to spawn_blocking above 50 * KB
    for size in [KB, 50 * KB, 51 * KB, 1024 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            move |b, &size| {
                let hash = sodoken::legacy::BufWrite::new_no_lock(
                    sodoken::legacy::hash::blake2b::BYTES_MIN,
                );
                let data = sodoken::legacy::BufWrite::new_no_lock(size);
                b.iter(move || {
                    blake2b(black_box(hash.clone()), black_box(data.clone()));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
