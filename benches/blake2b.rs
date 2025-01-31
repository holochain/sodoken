use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
    Throughput,
};

fn bench(c: &mut Criterion) {
    static KB: usize = 1024;

    let mut group = c.benchmark_group("blake2b");
    for size in [KB, 50 * KB, 51 * KB, 1024 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            move |b, &size| {
                let mut hash = vec![0; sodoken::blake2b::BYTES_MIN];
                let data = vec![0xdb; size];
                b.iter(move || {
                    black_box(
                        sodoken::blake2b::blake2b_hash(&mut hash, &data, None)
                            .unwrap(),
                    );
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
