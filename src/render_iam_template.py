import os
import yaml
import json
from jinja2 import Environment, FileSystemLoader

def load_policies(policies_dir):
    policies = []
    for filename in os.listdir(policies_dir):
        if filename.endswith('.json'):
            with open(os.path.join(policies_dir, filename)) as f:
                policies.append({
                    'name': filename,
                    'document': json.load(f)
                })
    return policies

def to_nice_yaml_block(value, indent=12):
    # Dump YAML, remove document separator, and indent every line
    yaml_str = yaml.dump(value, default_flow_style=False, sort_keys=False)
    yaml_str = yaml_str.replace('---\n', '')
    pad = ' ' * indent
    return ''.join(pad + line if line.strip() else line for line in yaml_str.splitlines(keepends=True))

def main():
    env = Environment(
        loader=FileSystemLoader('cloudformation'),
        trim_blocks=True,
        lstrip_blocks=True
    )
    env.filters['to_nice_yaml_block'] = to_nice_yaml_block
    template = env.get_template('iam_role.template.j2')

    with open('cloudformation/trust_policy.json') as f:
        trust_policy = json.load(f)

    policies = load_policies('policies')

    rendered = template.render(
        trust_policy=trust_policy,
        policies=policies
    )

    with open('cloudformation/iam_role.yaml', 'w') as f:
        f.write(rendered)

if __name__ == '__main__':
    main()
