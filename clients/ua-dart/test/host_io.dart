import 'dart:io';

String? readIfExists(String path) {
  final f = File(path);
  return f.existsSync() ? f.readAsStringSync() : null;
}

String cwd() => Directory.current.path;
String? env(String name) => Platform.environment[name];
