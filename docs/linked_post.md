I’ve spent the past year running GitHub Actions to deploy to AWS—and storing static AWS keys as GitHub repo secrets became a liability: long-lived credentials, manual rotations, and endless misconfigurations. I got tired of the toil, so I built [gha-aws-oidc-bootstrap](https://github.com/PaulDuvall/gha-aws-oidc-bootstrap) and open-sourced it.

With a single command, you can:

- 🚀 Spin up least-privilege IAM roles via CloudFormation  
- 🔗 Establish OIDC trust across any number of repos  
- ⚙️ Bootstrap your entire setup in one go

```bash
export GITHUB_TOKEN=github_pat_XXXXXXXXXXXX
bash run.sh --github-org <your_org> --region us-east-1 --github-token $GITHUB_TOKEN
```

- The script uses the file `allowed_repos.txt` to determine which repositories will be granted access. List each repository (in the format `owner/repo`) on a separate line in that file before running the script.
- There is no `--repos` argument; repository access is controlled via the trust policy and the contents of `allowed_repos.txt`.

No more static secrets—just short-lived, on-demand AWS credentials that enforce least privilege by design. Whether you’re managing one repo or hundreds, this scales with your needs.

Check it out, star the repo, and let me know what you think. 

🔗 https://github.com/PaulDuvall/gha-aws-oidc-bootstrap