# spin-go-aws

Requirements:

- [Spin v2.4.+](https://github.com/fermyon/spin/releases/tag/v2.4.2)

## Setting variables for the applications

> Use of the new feature that allows you to substitute variables into the `allowed_outbound_hosts` value in the `spin.toml` requires at least `v2.4.+` of Spin otherwise you will get errors when running `spin up`. 

Variables are defined in `spin.toml` under the `variables` table towards the top of the manifest. When developing locally you can set the variables without committing them to source by setting environment variables like `export SPIN_VARIABLE_<variable-name>="value"` in the same shell you use to run spin commands.

To set the variables manually you can use this script to create a `.envrc` file and source it before running `spin up`:

```shell
cat << EOF > .envrc
export SPIN_VARIABLE_AWS_ACCESS_KEY_ID="<insert-value-here>"
export SPIN_VARIABLE_AWS_SECRET_ACCESS_KEY="<insert-value-here>"
export SPIN_VARIABLE_AWS_SESSION_TOKEN="<insert-value-here>"
export SPIN_VARIABLE_AWS_DEFAULT_REGION="<insert-value-here>"
EOF
source .envrc
```

If you know the usual `AWS_*` variables will already be set in your shell you can also use this:

```shell
cat << EOF > .envrc
export SPIN_VARIABLE_AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
export SPIN_VARIABLE_AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
export SPIN_VARIABLE_AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN"
export SPIN_VARIABLE_AWS_DEFAULT_REGION="us-east-1"
EOF
source .envrc
```

To auto-load these variables you can use a tool like direnv to automatically export these variables in your shell.

```shell
cat << 'EOF' > .envrc
export SPIN_VARIABLE_AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
export SPIN_VARIABLE_AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
export SPIN_VARIABLE_AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN"
export SPIN_VARIABLE_AWS_DEFAULT_REGION="us-east-1"
EOF
direnv allow
```

Another method to set variables locally is to create a `.env` file next to the `spin.toml` file and when you run `spin up` it will automatically be read as variables for your application.

```shell
cat << EOF > aws-no-sdk/.env
aws_access_key_id="<insert-value-here>"
aws_secret_access_key="<insert-value-here>"
aws_session_token="<insert-value-here>"
aws_default_region="us-east-1"
EOF
```
