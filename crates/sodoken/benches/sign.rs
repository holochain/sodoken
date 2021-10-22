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

fn keypair(
    pk: sodoken::BufWriteSized<{ sodoken::sign::PUBLICKEYBYTES }>,
    sk: sodoken::BufWriteSized<{ sodoken::sign::SECRETKEYBYTES }>,
) {
    TOKIO.block_on(async move {
        sodoken::sign::keypair(pk, sk).await.unwrap();
    });
}

fn seed_keypair(
    pk: sodoken::BufWriteSized<{ sodoken::sign::PUBLICKEYBYTES }>,
    sk: sodoken::BufWriteSized<{ sodoken::sign::SECRETKEYBYTES }>,
    s: sodoken::BufWriteSized<{ sodoken::sign::SEEDBYTES }>,
) {
    TOKIO.block_on(async move {
        sodoken::sign::seed_keypair(pk, sk, s).await.unwrap();
    });
}

fn detached(
    sig: sodoken::BufWriteSized<{ sodoken::sign::BYTES }>,
    msg: sodoken::BufWrite,
    sk: sodoken::BufWriteSized<{ sodoken::sign::SECRETKEYBYTES }>,
) {
    TOKIO.block_on(async move {
        sodoken::sign::detached(sig, msg, sk).await.unwrap();
    });
}

fn verify_detached(
    sig: sodoken::BufWriteSized<{ sodoken::sign::BYTES }>,
    msg: sodoken::BufWrite,
    pk: sodoken::BufWriteSized<{ sodoken::sign::PUBLICKEYBYTES }>,
) {
    TOKIO.block_on(async move {
        sodoken::sign::verify_detached(sig, msg, pk).await.unwrap();
    });
}

fn bench(c: &mut Criterion) {
    static KB: usize = 1024;

    let mut group = c.benchmark_group("keypair");

    group.bench_function("keypair", move |b| {
        let pk = sodoken::BufWriteSized::new_no_lock();
        let sk = sodoken::BufWriteSized::new_no_lock();
        b.iter(move || {
            keypair(black_box(pk.clone()), black_box(sk.clone()));
        });
    });

    group.bench_function("seed_keypair", move |b| {
        let pk = sodoken::BufWriteSized::new_no_lock();
        let sk = sodoken::BufWriteSized::new_no_lock();
        let s = sodoken::BufWriteSized::new_no_lock();
        b.iter(move || {
            seed_keypair(
                black_box(pk.clone()),
                black_box(sk.clone()),
                black_box(s.clone()),
            );
        });
    });

    group.finish();

    let mut group = c.benchmark_group("detached");
    // CURRENTLY we switch over to spawn_blocking above 10 * KB
    for size in [KB, 10 * KB, 11 * KB, 20 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            move |b, &size| {
                let pk = sodoken::BufWriteSized::new_no_lock();
                let sk = sodoken::BufWriteSized::new_no_lock();
                let fut = sodoken::sign::keypair(pk.clone(), sk.clone());
                TOKIO.block_on(fut).unwrap();
                let msg = sodoken::BufWrite::new_no_lock(size);
                let sig = sodoken::BufWriteSized::new_no_lock();
                b.iter(move || {
                    detached(
                        black_box(sig.clone()),
                        black_box(msg.clone()),
                        black_box(sk.clone()),
                    );
                });
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("verify_detached");
    // CURRENTLY we switch over to spawn_blocking above 10 * KB
    for size in [KB, 10 * KB, 11 * KB, 20 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            move |b, &size| {
                let pk = sodoken::BufWriteSized::new_no_lock();
                let sk = sodoken::BufWriteSized::new_no_lock();
                let fut = sodoken::sign::keypair(pk.clone(), sk.clone());
                TOKIO.block_on(fut).unwrap();
                let msg = sodoken::BufWrite::new_no_lock(size);
                let sig = sodoken::BufWriteSized::new_no_lock();
                let fut = sodoken::sign::detached(sig.clone(), msg.clone(), sk);
                TOKIO.block_on(fut).unwrap();
                b.iter(move || {
                    verify_detached(
                        black_box(sig.clone()),
                        black_box(msg.clone()),
                        black_box(pk.clone()),
                    );
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
