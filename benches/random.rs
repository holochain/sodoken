use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
    Throughput,
};

fn bench(c: &mut Criterion) {
    static KB: usize = 1024;

    let mut group = c.benchmark_group("random");
    for size in [KB, 10 * KB, 11 * KB, 20 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            move |b, &size| {
                let mut buf = vec![0; size];
                b.iter(move || {
                    black_box(
                        sodoken::random::randombytes_buf(&mut buf).unwrap(),
                    );
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
