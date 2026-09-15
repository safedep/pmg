from pathlib import Path
import sys

path = Path(sys.argv[1]) / 'ptyx_windows.go'
source = path.read_text()
if 'func (s *winSession) waitProcess(' not in source:
    start = source.index('\tgo func() {\n\t\tst, err := windows.WaitForSingleObject(pi.Process, windows.INFINITE)')
    end = source.index('\n\t}()', start) + len('\n\t}()')
    body = source[start + len('\tgo func() {\n'):end - len('\n\t}()')]
    body = '\n'.join(line[1:] for line in body.splitlines())
    body = body.replace('pi.Process', 'process').replace('sess.', 's.')
    source = source[:start] + '\tgo sess.waitProcess(pi.Process, pi.Thread)' + source[end:]
    source += '\nfunc (s *winSession) waitProcess(process, thread windows.Handle) {\n' + body + '\n}\n'
    path.write_text(source)
    print('Extracted the existing waiter without changing its behavior for the controlled fixture')
