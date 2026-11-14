pub(crate) fn require_absent<T, E: std::fmt::Display>(
    result: Result<Option<T>, E>,
) -> Result<(), String> {
    match result {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err("unique unavailable service unexpectedly exists".into()),
        Err(error) => Err(format!("ServiceManager transaction failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_successful_null_reply_proves_absence() {
        assert!(require_absent::<(), &str>(Ok(None)).is_ok());
        assert!(require_absent::<(), &str>(Ok(Some(()))).is_err());
        for error in [
            "NameNotFound",
            "DeadObject",
            "FailedTransaction",
            "PermissionDenied",
        ] {
            assert_eq!(
                require_absent::<(), _>(Err(error)).unwrap_err(),
                format!("ServiceManager transaction failed: {error}")
            );
        }
    }
}
