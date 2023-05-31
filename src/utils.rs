use anyhow::Result;

pub fn split_repo_full_name(repo_full_name: &Option<String>) -> Result<(String, String)> {
    match repo_full_name {
        Some(repo_full_name) => {
            let v: Vec<&str> = repo_full_name.split("/").collect();
            Ok((v[0].to_string(), v[1].to_string()))
        }
        None => Err(anyhow::anyhow!("No repository name provided")),
    }
}
