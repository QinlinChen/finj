from jinja2 import Environment, FileSystemLoader
import os
import argparse


class FuncInfo:

    def __init__(self, name, ret_type, params, ret_val, errnos):
        self.name = name
        self.ret_type = ret_type
        self.params = params
        self.ret_val = ret_val
        self.errnos = errnos

    @staticmethod
    def from_text(s):
        s = s.strip()
        fields = [field.strip() for field in s.split('|')]
        if len(fields) != 5:
            raise ValueError('Data format error "{}"'.format(s))

        # Parse each field.
        name, ret_type, ret_val = fields[0], fields[1], fields[3]
        params, errnos = [], []
        if len(fields[2]):
            params = [param.strip() for param in fields[2].split(',')]
            if len(params) % 2 != 0:
                raise ValueError('Paramters format error')
            params = list(zip(params[::2], params[1::2]))
        if len(fields[4]):
            errnos = [errno.strip() for errno in fields[4].split(',')]

        return FuncInfo(name, ret_type, params, ret_val, errnos)

    def has_params(self):
        return len(self.params)

    def params_str(self):
        return ', '.join(['{0} {1}'.format(*param) for param in self.params])

    def args_str(self):
        return ', '.join([param[1] for param in self.params])

    def errnos_str(self):
        return ', '.join([errno for errno in self.errnos])

    def signature_str(self, hack_prefix=''):
        if len(hack_prefix) != 0:
            hack_prefix += '_'
        return '{self.ret_type} {prefix}{self.name}({params})'.format(
            self=self, prefix=hack_prefix, params=self.params_str())

    def __str__(self):
        return '{}: {}\n    {}'.format(
            self.signature_str(), self.ret_val, self.errnos_str())


def module_path(*paths):
    '''Generate a relative path to the current module.'''
    module_dir = os.path.dirname(__file__)
    if not paths:
        return module_dir
    return os.path.join(module_dir, *paths)


def is_valid_line(line):
    line = line.strip()
    return len(line) > 0 and line[0] != '#'


def load_func_infos(datafile):
    with open(datafile, 'r') as f:
        return [FuncInfo.from_text(line) for line in f if is_valid_line(line)]


def render_template(env, src, dst, **kwargs):
    template = env.get_template(src)
    with open(dst, 'w') as f:
        f.write(template.render(**kwargs))


def genhook(datafile, template_dir, templates, output_dir):
    func_infos = load_func_infos(datafile)
    env = Environment(loader=FileSystemLoader(template_dir))

    for template in templates:
        output = os.path.join(output_dir, template)
        render_template(env, template, output, func_infos=func_infos)


def parse_args():
    parser = argparse.ArgumentParser(description='Hook Generator')
    parser.add_argument('-d', '--data', required=True,
                        help='the data file containing the infomation of hook functions')
    parser.add_argument('-i', '--in-dir', dest='in_dir',
                        default=module_path('templates'),
                        help='the directory where templates are read from')
    parser.add_argument('-o', '--out-dir', dest='out_dir',
                        default=module_path(),
                        help='the directory where templates are rendered to')
    parser.add_argument('templates', nargs='+',
                        help='template files')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    genhook(args.data, args.in_dir, args.templates, args.out_dir)
