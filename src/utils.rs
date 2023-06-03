use anyhow::Result;

pub fn split_repo_full_name(repo_full_name: &Option<String>) -> Result<(String, String)> {
    match repo_full_name {
        Some(repo_full_name) => {
            split_some_repo_full_name(&repo_full_name)
        }
        None => Err(anyhow::anyhow!("No repository name provided")),
    }
}

pub fn split_some_repo_full_name(repo_full_name: &String) -> Result<(String, String)> {
    let v: Vec<&str> = repo_full_name.split("/").collect();
    if v.len() != 2 {
        return Err(anyhow::anyhow!("Invalid repository name: {}", repo_full_name));
    }
    Ok((v[0].to_string(), v[1].to_string()))
}
