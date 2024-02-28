use crate::common::cut_path;
use sp_core::crypto::DeriveJunction;

#[test]
fn cut_path_test() {
    let path_and_pwd =
        "//alice/soft//hard//some_extraordinarily_long_derivation_just_for_test///secret_password";
    let cut = cut_path(path_and_pwd).unwrap();
    assert_eq!(cut.junctions.len(), 4);
    assert!(cut.junctions[0].is_hard());
    assert_eq!(
        cut.junctions[0].inner(),
        DeriveJunction::hard("alice").unwrap_inner()
    );
    assert!(cut.junctions[1].is_soft());
    assert_eq!(
        cut.junctions[1].inner(),
        DeriveJunction::soft("soft").unwrap_inner()
    );
    assert!(cut.junctions[2].is_hard());
    assert_eq!(
        cut.junctions[2].inner(),
        DeriveJunction::hard("hard").unwrap_inner()
    );
    assert!(cut.junctions[3].is_hard());
    assert_eq!(
        cut.junctions[3].inner(),
        DeriveJunction::hard("some_extraordinarily_long_derivation_just_for_test").unwrap_inner()
    );
    assert_eq!(cut.password.unwrap(), "secret_password");
}
