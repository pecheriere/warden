use warden_broker_proto::InfoResponse;
use warden_broker_proto::signing::Audience;

use super::{permissions_or_refuse, scoped_or_refuse};
use crate::client::CallError;
use crate::{EXIT_ERROR, Exit};

fn info(scoped: bool) -> InfoResponse {
    InfoResponse {
        github_token_max_window: None,
        scoped_github_tokens: scoped,
        github_token_permissions: scoped,
        protocols: Vec::new(),
        audience: Audience::try_from("40ad20029e94984d193159667b296d8a".to_owned()).unwrap(),
    }
}

#[test]
fn a_broker_that_scopes_grants_is_accepted() {
    assert!(scoped_or_refuse(Ok(info(true))).is_ok());
}

#[test]
fn an_old_broker_or_one_that_cannot_be_asked_is_refused() {
    for answer in [
        Ok(info(false)),
        Err(CallError::Unavailable("cannot reach the broker".to_owned())),
        Err(CallError::Refused("broker refused (404)".to_owned())),
    ] {
        let e = scoped_or_refuse(answer).unwrap_err();
        let exit = e.downcast_ref::<Exit>().unwrap();
        assert_eq!(exit.code, EXIT_ERROR);
        assert_eq!(
            exit.message,
            "the broker does not support repository-scoped GitHub grants: upgrade the broker \
             before asking for GitHub access"
        );
    }
}

#[test]
fn a_broker_with_extra_permissions_is_accepted() {
    assert!(permissions_or_refuse(Ok(info(true))).is_ok());
}

#[test]
fn a_broker_without_extra_permissions_says_upgrade() {
    let mut old = info(true);
    old.github_token_permissions = false;
    for answer in [Ok(old), Err(CallError::Unavailable("down".to_owned()))] {
        let error = permissions_or_refuse(answer).unwrap_err();
        let exit = error.downcast_ref::<Exit>().expect("an exit");
        assert_eq!(exit.code, EXIT_ERROR);
        assert!(
            exit.message.contains("upgrade the broker"),
            "{}",
            exit.message
        );
        assert!(
            exit.message.contains("extra GitHub permissions"),
            "{}",
            exit.message
        );
    }
}
