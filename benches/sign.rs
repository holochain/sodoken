use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
    Throughput,
};

fn bench(c: &mut Criterion) {
    static KB: usize = 1024;

    let mut group = c.benchmark_group("keypair");

    group.bench_function("keypair", move |b| {
        let mut pk = [0_u8; sodoken::sign::PUBLICKEYBYTES];
        let mut sk = sodoken::LockedArray::new().unwrap();
        b.iter(move || {
            black_box(sodoken::sign::keypair(&mut pk, &mut sk.lock()).unwrap());
        });
    });

    group.bench_function("seed_keypair", move |b| {
        let mut pk = [0_u8; sodoken::sign::PUBLICKEYBYTES];
        let mut sk = sodoken::LockedArray::new().unwrap();
        b.iter(move || {
            black_box(
                sodoken::sign::seed_keypair(
                    &mut pk,
                    &mut sk.lock(),
                    &[0xdb; 32],
                )
                .unwrap(),
            );
        });
    });

    group.finish();

    let mut group = c.benchmark_group("sign_detached");
    for size in [KB, 10 * KB, 11 * KB, 20 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            move |b, &size| {
                let msg = vec![0xdb; size];
                let mut pk = [0_u8; sodoken::sign::PUBLICKEYBYTES];
                let mut sk = sodoken::LockedArray::new().unwrap();
                sodoken::sign::keypair(&mut pk, &mut sk.lock()).unwrap();
                let mut sig = [0_u8; sodoken::sign::SIGNATUREBYTES];
                b.iter(move || {
                    black_box(
                        sodoken::sign::sign_detached(
                            &mut sig,
                            &msg,
                            &sk.lock(),
                        )
                        .unwrap(),
                    );
                });
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("verify_detached");
    for size in [KB, 10 * KB, 11 * KB, 20 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            move |b, &size| {
                let msg = vec![0xdb; size];
                let mut pk = [0_u8; sodoken::sign::PUBLICKEYBYTES];
                let mut sk = sodoken::LockedArray::new().unwrap();
                sodoken::sign::keypair(&mut pk, &mut sk.lock()).unwrap();
                let mut sig = [0_u8; sodoken::sign::SIGNATUREBYTES];
                sodoken::sign::sign_detached(&mut sig, &msg, &sk.lock())
                    .unwrap();
                b.iter(move || {
                    black_box(assert!(sodoken::sign::verify_detached(
                        &sig, &msg, &pk
                    )));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
