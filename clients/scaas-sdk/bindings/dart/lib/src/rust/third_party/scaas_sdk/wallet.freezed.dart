// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'wallet.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$ExecuteCall {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ExecuteCall);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'ExecuteCall()';
}


}

/// @nodoc
class $ExecuteCallCopyWith<$Res>  {
$ExecuteCallCopyWith(ExecuteCall _, $Res Function(ExecuteCall) __);
}


/// Adds pattern-matching-related methods to [ExecuteCall].
extension ExecuteCallPatterns on ExecuteCall {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( ExecuteCall_Transfer value)?  transfer,TResult Function( ExecuteCall_Opaque value)?  opaque,required TResult orElse(),}){
final _that = this;
switch (_that) {
case ExecuteCall_Transfer() when transfer != null:
return transfer(_that);case ExecuteCall_Opaque() when opaque != null:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( ExecuteCall_Transfer value)  transfer,required TResult Function( ExecuteCall_Opaque value)  opaque,}){
final _that = this;
switch (_that) {
case ExecuteCall_Transfer():
return transfer(_that);case ExecuteCall_Opaque():
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( ExecuteCall_Transfer value)?  transfer,TResult? Function( ExecuteCall_Opaque value)?  opaque,}){
final _that = this;
switch (_that) {
case ExecuteCall_Transfer() when transfer != null:
return transfer(_that);case ExecuteCall_Opaque() when opaque != null:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String token,  String to,  String amount)?  transfer,TResult Function( String target,  String value,  String data,  AllowOpaqueCall? allow)?  opaque,required TResult orElse(),}) {final _that = this;
switch (_that) {
case ExecuteCall_Transfer() when transfer != null:
return transfer(_that.token,_that.to,_that.amount);case ExecuteCall_Opaque() when opaque != null:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String token,  String to,  String amount)  transfer,required TResult Function( String target,  String value,  String data,  AllowOpaqueCall? allow)  opaque,}) {final _that = this;
switch (_that) {
case ExecuteCall_Transfer():
return transfer(_that.token,_that.to,_that.amount);case ExecuteCall_Opaque():
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String token,  String to,  String amount)?  transfer,TResult? Function( String target,  String value,  String data,  AllowOpaqueCall? allow)?  opaque,}) {final _that = this;
switch (_that) {
case ExecuteCall_Transfer() when transfer != null:
return transfer(_that.token,_that.to,_that.amount);case ExecuteCall_Opaque() when opaque != null:
return opaque(_that.target,_that.value,_that.data,_that.allow);case _:
  return null;

}
}

}

/// @nodoc


class ExecuteCall_Transfer extends ExecuteCall {
  const ExecuteCall_Transfer({required this.token, required this.to, required this.amount}): super._();
  

 final  String token;
 final  String to;
 final  String amount;

/// Create a copy of ExecuteCall
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ExecuteCall_TransferCopyWith<ExecuteCall_Transfer> get copyWith => _$ExecuteCall_TransferCopyWithImpl<ExecuteCall_Transfer>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ExecuteCall_Transfer&&(identical(other.token, token) || other.token == token)&&(identical(other.to, to) || other.to == to)&&(identical(other.amount, amount) || other.amount == amount));
}


@override
int get hashCode => Object.hash(runtimeType,token,to,amount);

@override
String toString() {
  return 'ExecuteCall.transfer(token: $token, to: $to, amount: $amount)';
}


}

/// @nodoc
abstract mixin class $ExecuteCall_TransferCopyWith<$Res> implements $ExecuteCallCopyWith<$Res> {
  factory $ExecuteCall_TransferCopyWith(ExecuteCall_Transfer value, $Res Function(ExecuteCall_Transfer) _then) = _$ExecuteCall_TransferCopyWithImpl;
@useResult
$Res call({
 String token, String to, String amount
});




}
/// @nodoc
class _$ExecuteCall_TransferCopyWithImpl<$Res>
    implements $ExecuteCall_TransferCopyWith<$Res> {
  _$ExecuteCall_TransferCopyWithImpl(this._self, this._then);

  final ExecuteCall_Transfer _self;
  final $Res Function(ExecuteCall_Transfer) _then;

/// Create a copy of ExecuteCall
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? token = null,Object? to = null,Object? amount = null,}) {
  return _then(ExecuteCall_Transfer(
token: null == token ? _self.token : token // ignore: cast_nullable_to_non_nullable
as String,to: null == to ? _self.to : to // ignore: cast_nullable_to_non_nullable
as String,amount: null == amount ? _self.amount : amount // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class ExecuteCall_Opaque extends ExecuteCall {
  const ExecuteCall_Opaque({required this.target, required this.value, required this.data, this.allow}): super._();
  

 final  String target;
 final  String value;
 final  String data;
 final  AllowOpaqueCall? allow;

/// Create a copy of ExecuteCall
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ExecuteCall_OpaqueCopyWith<ExecuteCall_Opaque> get copyWith => _$ExecuteCall_OpaqueCopyWithImpl<ExecuteCall_Opaque>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ExecuteCall_Opaque&&(identical(other.target, target) || other.target == target)&&(identical(other.value, value) || other.value == value)&&(identical(other.data, data) || other.data == data)&&(identical(other.allow, allow) || other.allow == allow));
}


@override
int get hashCode => Object.hash(runtimeType,target,value,data,allow);

@override
String toString() {
  return 'ExecuteCall.opaque(target: $target, value: $value, data: $data, allow: $allow)';
}


}

/// @nodoc
abstract mixin class $ExecuteCall_OpaqueCopyWith<$Res> implements $ExecuteCallCopyWith<$Res> {
  factory $ExecuteCall_OpaqueCopyWith(ExecuteCall_Opaque value, $Res Function(ExecuteCall_Opaque) _then) = _$ExecuteCall_OpaqueCopyWithImpl;
@useResult
$Res call({
 String target, String value, String data, AllowOpaqueCall? allow
});




}
/// @nodoc
class _$ExecuteCall_OpaqueCopyWithImpl<$Res>
    implements $ExecuteCall_OpaqueCopyWith<$Res> {
  _$ExecuteCall_OpaqueCopyWithImpl(this._self, this._then);

  final ExecuteCall_Opaque _self;
  final $Res Function(ExecuteCall_Opaque) _then;

/// Create a copy of ExecuteCall
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? target = null,Object? value = null,Object? data = null,Object? allow = freezed,}) {
  return _then(ExecuteCall_Opaque(
target: null == target ? _self.target : target // ignore: cast_nullable_to_non_nullable
as String,value: null == value ? _self.value : value // ignore: cast_nullable_to_non_nullable
as String,data: null == data ? _self.data : data // ignore: cast_nullable_to_non_nullable
as String,allow: freezed == allow ? _self.allow : allow // ignore: cast_nullable_to_non_nullable
as AllowOpaqueCall?,
  ));
}


}

/// @nodoc
mixin _$PayBody {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PayBody);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'PayBody()';
}


}

/// @nodoc
class $PayBodyCopyWith<$Res>  {
$PayBodyCopyWith(PayBody _, $Res Function(PayBody) __);
}


/// Adds pattern-matching-related methods to [PayBody].
extension PayBodyPatterns on PayBody {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( PayBody_None value)?  none,TResult Function( PayBody_Note value)?  note,TResult Function( PayBody_CreditorRef value)?  creditorRef,TResult Function( PayBody_BoundCall value)?  boundCall,TResult Function( PayBody_Ciphertext value)?  ciphertext,required TResult orElse(),}){
final _that = this;
switch (_that) {
case PayBody_None() when none != null:
return none(_that);case PayBody_Note() when note != null:
return note(_that);case PayBody_CreditorRef() when creditorRef != null:
return creditorRef(_that);case PayBody_BoundCall() when boundCall != null:
return boundCall(_that);case PayBody_Ciphertext() when ciphertext != null:
return ciphertext(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( PayBody_None value)  none,required TResult Function( PayBody_Note value)  note,required TResult Function( PayBody_CreditorRef value)  creditorRef,required TResult Function( PayBody_BoundCall value)  boundCall,required TResult Function( PayBody_Ciphertext value)  ciphertext,}){
final _that = this;
switch (_that) {
case PayBody_None():
return none(_that);case PayBody_Note():
return note(_that);case PayBody_CreditorRef():
return creditorRef(_that);case PayBody_BoundCall():
return boundCall(_that);case PayBody_Ciphertext():
return ciphertext(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( PayBody_None value)?  none,TResult? Function( PayBody_Note value)?  note,TResult? Function( PayBody_CreditorRef value)?  creditorRef,TResult? Function( PayBody_BoundCall value)?  boundCall,TResult? Function( PayBody_Ciphertext value)?  ciphertext,}){
final _that = this;
switch (_that) {
case PayBody_None() when none != null:
return none(_that);case PayBody_Note() when note != null:
return note(_that);case PayBody_CreditorRef() when creditorRef != null:
return creditorRef(_that);case PayBody_BoundCall() when boundCall != null:
return boundCall(_that);case PayBody_Ciphertext() when ciphertext != null:
return ciphertext(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  none,TResult Function( String note)?  note,TResult Function( String creditorRef,  BigInt dueDate)?  creditorRef,TResult Function( String chainId,  String target,  String callHash)?  boundCall,TResult Function( String ciphertext)?  ciphertext,required TResult orElse(),}) {final _that = this;
switch (_that) {
case PayBody_None() when none != null:
return none();case PayBody_Note() when note != null:
return note(_that.note);case PayBody_CreditorRef() when creditorRef != null:
return creditorRef(_that.creditorRef,_that.dueDate);case PayBody_BoundCall() when boundCall != null:
return boundCall(_that.chainId,_that.target,_that.callHash);case PayBody_Ciphertext() when ciphertext != null:
return ciphertext(_that.ciphertext);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  none,required TResult Function( String note)  note,required TResult Function( String creditorRef,  BigInt dueDate)  creditorRef,required TResult Function( String chainId,  String target,  String callHash)  boundCall,required TResult Function( String ciphertext)  ciphertext,}) {final _that = this;
switch (_that) {
case PayBody_None():
return none();case PayBody_Note():
return note(_that.note);case PayBody_CreditorRef():
return creditorRef(_that.creditorRef,_that.dueDate);case PayBody_BoundCall():
return boundCall(_that.chainId,_that.target,_that.callHash);case PayBody_Ciphertext():
return ciphertext(_that.ciphertext);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  none,TResult? Function( String note)?  note,TResult? Function( String creditorRef,  BigInt dueDate)?  creditorRef,TResult? Function( String chainId,  String target,  String callHash)?  boundCall,TResult? Function( String ciphertext)?  ciphertext,}) {final _that = this;
switch (_that) {
case PayBody_None() when none != null:
return none();case PayBody_Note() when note != null:
return note(_that.note);case PayBody_CreditorRef() when creditorRef != null:
return creditorRef(_that.creditorRef,_that.dueDate);case PayBody_BoundCall() when boundCall != null:
return boundCall(_that.chainId,_that.target,_that.callHash);case PayBody_Ciphertext() when ciphertext != null:
return ciphertext(_that.ciphertext);case _:
  return null;

}
}

}

/// @nodoc


class PayBody_None extends PayBody {
  const PayBody_None(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PayBody_None);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'PayBody.none()';
}


}




/// @nodoc


class PayBody_Note extends PayBody {
  const PayBody_Note({required this.note}): super._();
  

 final  String note;

/// Create a copy of PayBody
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PayBody_NoteCopyWith<PayBody_Note> get copyWith => _$PayBody_NoteCopyWithImpl<PayBody_Note>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PayBody_Note&&(identical(other.note, note) || other.note == note));
}


@override
int get hashCode => Object.hash(runtimeType,note);

@override
String toString() {
  return 'PayBody.note(note: $note)';
}


}

/// @nodoc
abstract mixin class $PayBody_NoteCopyWith<$Res> implements $PayBodyCopyWith<$Res> {
  factory $PayBody_NoteCopyWith(PayBody_Note value, $Res Function(PayBody_Note) _then) = _$PayBody_NoteCopyWithImpl;
@useResult
$Res call({
 String note
});




}
/// @nodoc
class _$PayBody_NoteCopyWithImpl<$Res>
    implements $PayBody_NoteCopyWith<$Res> {
  _$PayBody_NoteCopyWithImpl(this._self, this._then);

  final PayBody_Note _self;
  final $Res Function(PayBody_Note) _then;

/// Create a copy of PayBody
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? note = null,}) {
  return _then(PayBody_Note(
note: null == note ? _self.note : note // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class PayBody_CreditorRef extends PayBody {
  const PayBody_CreditorRef({required this.creditorRef, required this.dueDate}): super._();
  

 final  String creditorRef;
 final  BigInt dueDate;

/// Create a copy of PayBody
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PayBody_CreditorRefCopyWith<PayBody_CreditorRef> get copyWith => _$PayBody_CreditorRefCopyWithImpl<PayBody_CreditorRef>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PayBody_CreditorRef&&(identical(other.creditorRef, creditorRef) || other.creditorRef == creditorRef)&&(identical(other.dueDate, dueDate) || other.dueDate == dueDate));
}


@override
int get hashCode => Object.hash(runtimeType,creditorRef,dueDate);

@override
String toString() {
  return 'PayBody.creditorRef(creditorRef: $creditorRef, dueDate: $dueDate)';
}


}

/// @nodoc
abstract mixin class $PayBody_CreditorRefCopyWith<$Res> implements $PayBodyCopyWith<$Res> {
  factory $PayBody_CreditorRefCopyWith(PayBody_CreditorRef value, $Res Function(PayBody_CreditorRef) _then) = _$PayBody_CreditorRefCopyWithImpl;
@useResult
$Res call({
 String creditorRef, BigInt dueDate
});




}
/// @nodoc
class _$PayBody_CreditorRefCopyWithImpl<$Res>
    implements $PayBody_CreditorRefCopyWith<$Res> {
  _$PayBody_CreditorRefCopyWithImpl(this._self, this._then);

  final PayBody_CreditorRef _self;
  final $Res Function(PayBody_CreditorRef) _then;

/// Create a copy of PayBody
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? creditorRef = null,Object? dueDate = null,}) {
  return _then(PayBody_CreditorRef(
creditorRef: null == creditorRef ? _self.creditorRef : creditorRef // ignore: cast_nullable_to_non_nullable
as String,dueDate: null == dueDate ? _self.dueDate : dueDate // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class PayBody_BoundCall extends PayBody {
  const PayBody_BoundCall({required this.chainId, required this.target, required this.callHash}): super._();
  

 final  String chainId;
 final  String target;
 final  String callHash;

/// Create a copy of PayBody
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PayBody_BoundCallCopyWith<PayBody_BoundCall> get copyWith => _$PayBody_BoundCallCopyWithImpl<PayBody_BoundCall>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PayBody_BoundCall&&(identical(other.chainId, chainId) || other.chainId == chainId)&&(identical(other.target, target) || other.target == target)&&(identical(other.callHash, callHash) || other.callHash == callHash));
}


@override
int get hashCode => Object.hash(runtimeType,chainId,target,callHash);

@override
String toString() {
  return 'PayBody.boundCall(chainId: $chainId, target: $target, callHash: $callHash)';
}


}

/// @nodoc
abstract mixin class $PayBody_BoundCallCopyWith<$Res> implements $PayBodyCopyWith<$Res> {
  factory $PayBody_BoundCallCopyWith(PayBody_BoundCall value, $Res Function(PayBody_BoundCall) _then) = _$PayBody_BoundCallCopyWithImpl;
@useResult
$Res call({
 String chainId, String target, String callHash
});




}
/// @nodoc
class _$PayBody_BoundCallCopyWithImpl<$Res>
    implements $PayBody_BoundCallCopyWith<$Res> {
  _$PayBody_BoundCallCopyWithImpl(this._self, this._then);

  final PayBody_BoundCall _self;
  final $Res Function(PayBody_BoundCall) _then;

/// Create a copy of PayBody
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? chainId = null,Object? target = null,Object? callHash = null,}) {
  return _then(PayBody_BoundCall(
chainId: null == chainId ? _self.chainId : chainId // ignore: cast_nullable_to_non_nullable
as String,target: null == target ? _self.target : target // ignore: cast_nullable_to_non_nullable
as String,callHash: null == callHash ? _self.callHash : callHash // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class PayBody_Ciphertext extends PayBody {
  const PayBody_Ciphertext({required this.ciphertext}): super._();
  

 final  String ciphertext;

/// Create a copy of PayBody
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PayBody_CiphertextCopyWith<PayBody_Ciphertext> get copyWith => _$PayBody_CiphertextCopyWithImpl<PayBody_Ciphertext>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PayBody_Ciphertext&&(identical(other.ciphertext, ciphertext) || other.ciphertext == ciphertext));
}


@override
int get hashCode => Object.hash(runtimeType,ciphertext);

@override
String toString() {
  return 'PayBody.ciphertext(ciphertext: $ciphertext)';
}


}

/// @nodoc
abstract mixin class $PayBody_CiphertextCopyWith<$Res> implements $PayBodyCopyWith<$Res> {
  factory $PayBody_CiphertextCopyWith(PayBody_Ciphertext value, $Res Function(PayBody_Ciphertext) _then) = _$PayBody_CiphertextCopyWithImpl;
@useResult
$Res call({
 String ciphertext
});




}
/// @nodoc
class _$PayBody_CiphertextCopyWithImpl<$Res>
    implements $PayBody_CiphertextCopyWith<$Res> {
  _$PayBody_CiphertextCopyWithImpl(this._self, this._then);

  final PayBody_Ciphertext _self;
  final $Res Function(PayBody_Ciphertext) _then;

/// Create a copy of PayBody
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? ciphertext = null,}) {
  return _then(PayBody_Ciphertext(
ciphertext: null == ciphertext ? _self.ciphertext : ciphertext // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
