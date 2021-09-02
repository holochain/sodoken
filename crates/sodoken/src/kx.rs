//! Api functions related to cryptographically secure key exchange.

use crate::*;

/// Byte length of kx public key.
pub const KX_PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_kx_PUBLICKEYBYTES as usize;

/// Byte length of kx secret key.
pub const KX_SECRETKEYBYTES: usize =
    libsodium_sys::crypto_kx_SECRETKEYBYTES as usize;

/// Byte length of kx session key.
pub const KX_SESSIONKEYBYTES: usize =
    libsodium_sys::crypto_kx_SESSIONKEYBYTES as usize;

/// Generate a key exchange keypair.
pub fn keypair<P, S>(pub_key: P, sec_key: S) -> SodokenResult<()>
where
    P: Into<BufWriteSized<KX_PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufWriteSized<KX_SECRETKEYBYTES>> + 'static + Send,
{
    let pub_key = pub_key.into();
    let sec_key = sec_key.into();

    let mut pub_key = pub_key.write_lock_sized();
    let mut sec_key = sec_key.write_lock_sized();

    safe::sodium::crypto_kx_keypair(&mut pub_key, &mut sec_key)
}

/// Generate session keys from the client perspective.
pub fn client_session_keys<R, T, CPub, CSec, SPub>(
    rx: R,
    tx: T,
    client_pk: CPub,
    client_sk: CSec,
    server_pk: SPub,
) -> SodokenResult<()>
where
    R: Into<BufWriteSized<KX_SESSIONKEYBYTES>> + 'static + Send,
    T: Into<BufWriteSized<KX_SESSIONKEYBYTES>> + 'static + Send,
    CPub: Into<BufReadSized<KX_PUBLICKEYBYTES>> + 'static + Send,
    CSec: Into<BufReadSized<KX_SECRETKEYBYTES>> + 'static + Send,
    SPub: Into<BufReadSized<KX_PUBLICKEYBYTES>> + 'static + Send,
{
    let rx = rx.into();
    let tx = tx.into();
    let client_pk = client_pk.into();
    let client_sk = client_sk.into();
    let server_pk = server_pk.into();

    let mut rx = rx.write_lock_sized();
    let mut tx = tx.write_lock_sized();
    let client_pk = client_pk.read_lock_sized();
    let client_sk = client_sk.read_lock_sized();
    let server_pk = server_pk.read_lock_sized();

    safe::sodium::crypto_kx_client_session_keys(
        &mut rx, &mut tx, &client_pk, &client_sk, &server_pk,
    )
}

/// Generate session keys from the server perspective.
pub fn server_session_keys<R, T, SPub, SSec, CPub>(
    rx: R,
    tx: T,
    server_pk: SPub,
    server_sk: SSec,
    client_pk: CPub,
) -> SodokenResult<()>
where
    R: Into<BufWriteSized<KX_SESSIONKEYBYTES>> + 'static + Send,
    T: Into<BufWriteSized<KX_SESSIONKEYBYTES>> + 'static + Send,
    SPub: Into<BufReadSized<KX_PUBLICKEYBYTES>> + 'static + Send,
    SSec: Into<BufReadSized<KX_SECRETKEYBYTES>> + 'static + Send,
    CPub: Into<BufReadSized<KX_PUBLICKEYBYTES>> + 'static + Send,
{
    let rx = rx.into();
    let tx = tx.into();
    let server_pk = server_pk.into();
    let server_sk = server_sk.into();
    let client_pk = client_pk.into();

    let mut rx = rx.write_lock_sized();
    let mut tx = tx.write_lock_sized();
    let server_pk = server_pk.read_lock_sized();
    let server_sk = server_sk.read_lock_sized();
    let client_pk = client_pk.read_lock_sized();

    safe::sodium::crypto_kx_server_session_keys(
        &mut rx, &mut tx, &server_pk, &server_sk, &client_pk,
    )
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_kx() -> SodokenResult<()> {
        let pk_srv = BufWriteSized::new_no_lock();
        let sk_srv = BufWriteSized::new_no_lock();
        kx::keypair(pk_srv.clone(), sk_srv.clone()).unwrap();

        let pk_cli = BufWriteSized::new_no_lock();
        let sk_cli = BufWriteSized::new_no_lock();
        kx::keypair(pk_cli.clone(), sk_cli.clone()).unwrap();

        let cli_rx = BufWriteSized::new_no_lock();
        let cli_tx = BufWriteSized::new_no_lock();
        kx::client_session_keys(
            cli_rx.clone(),
            cli_tx.clone(),
            pk_cli.clone(),
            sk_cli.clone(),
            pk_srv.clone(),
        )
        .unwrap();

        let srv_rx = BufWriteSized::new_no_lock();
        let srv_tx = BufWriteSized::new_no_lock();
        kx::server_session_keys(
            srv_rx.clone(),
            srv_tx.clone(),
            pk_srv.clone(),
            sk_srv.clone(),
            pk_cli.clone(),
        )
        .unwrap();

        assert_eq!(&*cli_rx.read_lock(), &*srv_tx.read_lock());
        assert_eq!(&*cli_tx.read_lock(), &*srv_rx.read_lock());

        Ok(())
    }
}
