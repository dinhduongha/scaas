// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'vault.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$Unlock {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Unlock);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'Unlock()';
}


}

/// @nodoc
class $UnlockCopyWith<$Res>  {
$UnlockCopyWith(Unlock _, $Res Function(Unlock) __);
}


/// Adds pattern-matching-related methods to [Unlock].
extension UnlockPatterns on Unlock {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( Unlock_Passphrase value)?  passphrase,TResult Function( Unlock_Passkey value)?  passkey,TResult Function( Unlock_Platform value)?  platform,required TResult orElse(),}){
final _that = this;
switch (_that) {
case Unlock_Passphrase() when passphrase != null:
return passphrase(_that);case Unlock_Passkey() when passkey != null:
return passkey(_that);case Unlock_Platform() when platform != null:
return platform(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( Unlock_Passphrase value)  passphrase,required TResult Function( Unlock_Passkey value)  passkey,required TResult Function( Unlock_Platform value)  platform,}){
final _that = this;
switch (_that) {
case Unlock_Passphrase():
return passphrase(_that);case Unlock_Passkey():
return passkey(_that);case Unlock_Platform():
return platform(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( Unlock_Passphrase value)?  passphrase,TResult? Function( Unlock_Passkey value)?  passkey,TResult? Function( Unlock_Platform value)?  platform,}){
final _that = this;
switch (_that) {
case Unlock_Passphrase() when passphrase != null:
return passphrase(_that);case Unlock_Passkey() when passkey != null:
return passkey(_that);case Unlock_Platform() when platform != null:
return platform(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( ArcSecretBytes field0)?  passphrase,TResult Function()?  passkey,TResult Function()?  platform,required TResult orElse(),}) {final _that = this;
switch (_that) {
case Unlock_Passphrase() when passphrase != null:
return passphrase(_that.field0);case Unlock_Passkey() when passkey != null:
return passkey();case Unlock_Platform() when platform != null:
return platform();case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( ArcSecretBytes field0)  passphrase,required TResult Function()  passkey,required TResult Function()  platform,}) {final _that = this;
switch (_that) {
case Unlock_Passphrase():
return passphrase(_that.field0);case Unlock_Passkey():
return passkey();case Unlock_Platform():
return platform();}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( ArcSecretBytes field0)?  passphrase,TResult? Function()?  passkey,TResult? Function()?  platform,}) {final _that = this;
switch (_that) {
case Unlock_Passphrase() when passphrase != null:
return passphrase(_that.field0);case Unlock_Passkey() when passkey != null:
return passkey();case Unlock_Platform() when platform != null:
return platform();case _:
  return null;

}
}

}

/// @nodoc


class Unlock_Passphrase extends Unlock {
  const Unlock_Passphrase(this.field0): super._();
  

 final  ArcSecretBytes field0;

/// Create a copy of Unlock
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Unlock_PassphraseCopyWith<Unlock_Passphrase> get copyWith => _$Unlock_PassphraseCopyWithImpl<Unlock_Passphrase>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Unlock_Passphrase&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'Unlock.passphrase(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $Unlock_PassphraseCopyWith<$Res> implements $UnlockCopyWith<$Res> {
  factory $Unlock_PassphraseCopyWith(Unlock_Passphrase value, $Res Function(Unlock_Passphrase) _then) = _$Unlock_PassphraseCopyWithImpl;
@useResult
$Res call({
 ArcSecretBytes field0
});




}
/// @nodoc
class _$Unlock_PassphraseCopyWithImpl<$Res>
    implements $Unlock_PassphraseCopyWith<$Res> {
  _$Unlock_PassphraseCopyWithImpl(this._self, this._then);

  final Unlock_Passphrase _self;
  final $Res Function(Unlock_Passphrase) _then;

/// Create a copy of Unlock
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(Unlock_Passphrase(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as ArcSecretBytes,
  ));
}


}

/// @nodoc


class Unlock_Passkey extends Unlock {
  const Unlock_Passkey(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Unlock_Passkey);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'Unlock.passkey()';
}


}




/// @nodoc


class Unlock_Platform extends Unlock {
  const Unlock_Platform(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Unlock_Platform);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'Unlock.platform()';
}


}




// dart format on
