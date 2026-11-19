// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'smart.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$SmartCall {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is SmartCall);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'SmartCall()';
}


}

/// @nodoc
class $SmartCallCopyWith<$Res>  {
$SmartCallCopyWith(SmartCall _, $Res Function(SmartCall) __);
}


/// Adds pattern-matching-related methods to [SmartCall].
extension SmartCallPatterns on SmartCall {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( SmartCall_Transfer value)?  transfer,TResult Function( SmartCall_InitiateRecovery value)?  initiateRecovery,TResult Function( SmartCall_Opaque value)?  opaque,required TResult orElse(),}){
final _that = this;
switch (_that) {
case SmartCall_Transfer() when transfer != null:
return transfer(_that);case SmartCall_InitiateRecovery() when initiateRecovery != null:
return initiateRecovery(_that);case SmartCall_Opaque() when opaque != null:
return opaque(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( SmartCall_Transfer value)  transfer,required TResult Function( SmartCall_InitiateRecovery value)  initiateRecovery,required TResult Function( SmartCall_Opaque value)  opaque,}){
final _that = this;
switch (_that) {
case SmartCall_Transfer():
return transfer(_that);case SmartCall_InitiateRecovery():
return initiateRecovery(_that);case SmartCall_Opaque():
return opaque(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( SmartCall_Transfer value)?  transfer,TResult? Function( SmartCall_InitiateRecovery value)?  initiateRecovery,TResult? Function( SmartCall_Opaque value)?  opaque,}){
final _that = this;
switch (_that) {
case SmartCall_Transfer() when transfer != null:
return transfer(_that);case SmartCall_InitiateRecovery() when initiateRecovery != null:
return initiateRecovery(_that);case SmartCall_Opaque() when opaque != null:
return opaque(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String token,  String to,  String amount)?  transfer,TResult Function( String account,  SubjectKeyArgs key)?  initiateRecovery,TResult Function( String target,  String value,  String data,  AllowOpaqueCall? allow)?  opaque,required TResult orElse(),}) {final _that = this;
switch (_that) {
case SmartCall_Transfer() when transfer != null:
return transfer(_that.token,_that.to,_that.amount);case SmartCall_InitiateRecovery() when initiateRecovery != null:
return initiateRecovery(_that.account,_that.key);case SmartCall_Opaque() when opaque != null:
return opaque(_that.target,_that.value,_that.data,_that.allow);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String token,  String to,  String amount)  transfer,required TResult Function( String account,  SubjectKeyArgs key)  initiateRecovery,required TResult Function( String target,  String value,  String data,  AllowOpaqueCall? allow)  opaque,}) {final _that = this;
switch (_that) {
case SmartCall_Transfer():
return transfer(_that.token,_that.to,_that.amount);case SmartCall_InitiateRecovery():
return initiateRecovery(_that.account,_that.key);case SmartCall_Opaque():
return opaque(_that.target,_that.value,_that.data,_that.allow);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String token,  String to,  String amount)?  transfer,TResult? Function( String account,  SubjectKeyArgs key)?  initiateRecovery,TResult? Function( String target,  String value,  String data,  AllowOpaqueCall? allow)?  opaque,}) {final _that = this;
switch (_that) {
case SmartCall_Transfer() when transfer != null:
return transfer(_that.token,_that.to,_that.amount);case SmartCall_InitiateRecovery() when initiateRecovery != null:
return initiateRecovery(_that.account,_that.key);case SmartCall_Opaque() when opaque != null:
return opaque(_that.target,_that.value,_that.data,_that.allow);case _:
  return null;

}
}

}

/// @nodoc


class SmartCall_Transfer extends SmartCall {
  const SmartCall_Transfer({required this.token, required this.to, required this.amount}): super._();
  

 final  String token;
 final  String to;
 final  String amount;

/// Create a copy of SmartCall
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SmartCall_TransferCopyWith<SmartCall_Transfer> get copyWith => _$SmartCall_TransferCopyWithImpl<SmartCall_Transfer>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is SmartCall_Transfer&&(identical(other.token, token) || other.token == token)&&(identical(other.to, to) || other.to == to)&&(identical(other.amount, amount) || other.amount == amount));
}


@override
int get hashCode => Object.hash(runtimeType,token,to,amount);

@override
String toString() {
  return 'SmartCall.transfer(token: $token, to: $to, amount: $amount)';
}


}

/// @nodoc
abstract mixin class $SmartCall_TransferCopyWith<$Res> implements $SmartCallCopyWith<$Res> {
  factory $SmartCall_TransferCopyWith(SmartCall_Transfer value, $Res Function(SmartCall_Transfer) _then) = _$SmartCall_TransferCopyWithImpl;
@useResult
$Res call({
 String token, String to, String amount
});




}
/// @nodoc
class _$SmartCall_TransferCopyWithImpl<$Res>
    implements $SmartCall_TransferCopyWith<$Res> {
  _$SmartCall_TransferCopyWithImpl(this._self, this._then);

  final SmartCall_Transfer _self;
  final $Res Function(SmartCall_Transfer) _then;

/// Create a copy of SmartCall
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? token = null,Object? to = null,Object? amount = null,}) {
  return _then(SmartCall_Transfer(
token: null == token ? _self.token : token // ignore: cast_nullable_to_non_nullable
as String,to: null == to ? _self.to : to // ignore: cast_nullable_to_non_nullable
as String,amount: null == amount ? _self.amount : amount // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class SmartCall_InitiateRecovery extends SmartCall {
  const SmartCall_InitiateRecovery({required this.account, required this.key}): super._();
  

 final  String account;
 final  SubjectKeyArgs key;

/// Create a copy of SmartCall
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SmartCall_InitiateRecoveryCopyWith<SmartCall_InitiateRecovery> get copyWith => _$SmartCall_InitiateRecoveryCopyWithImpl<SmartCall_InitiateRecovery>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is SmartCall_InitiateRecovery&&(identical(other.account, account) || other.account == account)&&(identical(other.key, key) || other.key == key));
}


@override
int get hashCode => Object.hash(runtimeType,account,key);

@override
String toString() {
  return 'SmartCall.initiateRecovery(account: $account, key: $key)';
}


}

/// @nodoc
abstract mixin class $SmartCall_InitiateRecoveryCopyWith<$Res> implements $SmartCallCopyWith<$Res> {
  factory $SmartCall_InitiateRecoveryCopyWith(SmartCall_InitiateRecovery value, $Res Function(SmartCall_InitiateRecovery) _then) = _$SmartCall_InitiateRecoveryCopyWithImpl;
@useResult
$Res call({
 String account, SubjectKeyArgs key
});




}
/// @nodoc
class _$SmartCall_InitiateRecoveryCopyWithImpl<$Res>
    implements $SmartCall_InitiateRecoveryCopyWith<$Res> {
  _$SmartCall_InitiateRecoveryCopyWithImpl(this._self, this._then);

  final SmartCall_InitiateRecovery _self;
  final $Res Function(SmartCall_InitiateRecovery) _then;

/// Create a copy of SmartCall
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? account = null,Object? key = null,}) {
  return _then(SmartCall_InitiateRecovery(
account: null == account ? _self.account : account // ignore: cast_nullable_to_non_nullable
as String,key: null == key ? _self.key : key // ignore: cast_nullable_to_non_nullable
as SubjectKeyArgs,
  ));
}


}

/// @nodoc


class SmartCall_Opaque extends SmartCall {
  const SmartCall_Opaque({required this.target, required this.value, required this.data, this.allow}): super._();
  

 final  String target;
 final  String value;
 final  String data;
 final  AllowOpaqueCall? allow;

/// Create a copy of SmartCall
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SmartCall_OpaqueCopyWith<SmartCall_Opaque> get copyWith => _$SmartCall_OpaqueCopyWithImpl<SmartCall_Opaque>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is SmartCall_Opaque&&(identical(other.target, target) || other.target == target)&&(identical(other.value, value) || other.value == value)&&(identical(other.data, data) || other.data == data)&&(identical(other.allow, allow) || other.allow == allow));
}


@override
int get hashCode => Object.hash(runtimeType,target,value,data,allow);

@override
String toString() {
  return 'SmartCall.opaque(target: $target, value: $value, data: $data, allow: $allow)';
}


}

/// @nodoc
abstract mixin class $SmartCall_OpaqueCopyWith<$Res> implements $SmartCallCopyWith<$Res> {
  factory $SmartCall_OpaqueCopyWith(SmartCall_Opaque value, $Res Function(SmartCall_Opaque) _then) = _$SmartCall_OpaqueCopyWithImpl;
@useResult
$Res call({
 String target, String value, String data, AllowOpaqueCall? allow
});




}
/// @nodoc
class _$SmartCall_OpaqueCopyWithImpl<$Res>
    implements $SmartCall_OpaqueCopyWith<$Res> {
  _$SmartCall_OpaqueCopyWithImpl(this._self, this._then);

  final SmartCall_Opaque _self;
  final $Res Function(SmartCall_Opaque) _then;

/// Create a copy of SmartCall
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? target = null,Object? value = null,Object? data = null,Object? allow = freezed,}) {
  return _then(SmartCall_Opaque(
target: null == target ? _self.target : target // ignore: cast_nullable_to_non_nullable
as String,value: null == value ? _self.value : value // ignore: cast_nullable_to_non_nullable
as String,data: null == data ? _self.data : data // ignore: cast_nullable_to_non_nullable
as String,allow: freezed == allow ? _self.allow : allow // ignore: cast_nullable_to_non_nullable
as AllowOpaqueCall?,
  ));
}


}

// dart format on
