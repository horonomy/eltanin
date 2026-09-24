//! ADR-0012 §11.4: Eltanin's adapter must state observe-mode semantics
//! are available on the MVP 2.0 development branch, never described as
//! shipped `main` behavior.

#[test]
fn branch_qualification_notice_names_the_dev_branch_not_main() {
    let notice = eltanin_dogfood::BRANCH_QUALIFICATION_NOTICE;
    assert!(
        notice.contains("next/mvp-2.0") || notice.contains("MVP 2.0 development branch"),
        "branch qualification notice must name the dev branch: {notice:?}"
    );
    assert!(
        notice.contains("not in a shipped main build") || notice.contains("not shipped"),
        "notice must explicitly disclaim shipped-main-build status: {notice:?}"
    );
}
