// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Host access for `dart test -p node` (no dart:io there): node's fs and process via js_interop.
import 'dart:js_interop';
import 'dart:js_interop_unsafe';

@JS('require')
external JSObject _require(String module);

extension type _Fs(JSObject _) implements JSObject {
  external bool existsSync(String p);
  external String readFileSync(String p, String enc);
}

extension type _Process(JSObject _) implements JSObject {
  external String cwd();
  external JSObject get env;
}

@JS('process')
external _Process get _process;

final _fs = _Fs(_require('fs'));

String? readIfExists(String path) => _fs.existsSync(path) ? _fs.readFileSync(path, 'utf8') : null;
String cwd() => _process.cwd();
String? env(String name) => (_process.env.getProperty(name.toJS) as JSString?)?.toDart;
