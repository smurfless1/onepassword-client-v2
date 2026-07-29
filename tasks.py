from invoke import task
import keyring


@task
def setup(c):
    """Bootstrap and maintain the dev environment."""
    c.run("mise install")
    c.run("uv sync")


@task
def test(c):
    c.run("uv run pytest --ignore=test/test_docker_from_outside.py")


@task
def lint(c):
    c.run("uv run black --check onepassword test")


@task
def build(c):
    c.run("uv build")


@task
def bump(_c, version_type="patch"):
    """Bump the VERSION file. version_type is 'patch' or 'minor'."""
    from onepassword.utils import bump_version

    bump_version(version_type=version_type)


@task
def publish(c):
    api_key = keyring.get_password('gitea API key', 'smurfless1')
    c.run(f"uv publish --index gitea --token {api_key}")
