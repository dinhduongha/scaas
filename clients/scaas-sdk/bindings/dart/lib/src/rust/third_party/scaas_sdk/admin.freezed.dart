// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'admin.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$RescueOp {

 BigInt get seq;
/// Create a copy of RescueOp
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$RescueOpCopyWith<RescueOp> get copyWith => _$RescueOpCopyWithImpl<RescueOp>(this as RescueOp, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is RescueOp&&(identical(other.seq, seq) || other.seq == seq));
}


@override
int get hashCode => Object.hash(runtimeType,seq);

@override
String toString() {
  return 'RescueOp(seq: $seq)';
}


}

/// @nodoc
abstract mixin class $RescueOpCopyWith<$Res>  {
  factory $RescueOpCopyWith(RescueOp value, $Res Function(RescueOp) _then) = _$RescueOpCopyWithImpl;
@useResult
$Res call({
 BigInt seq
});




}
/// @nodoc
class _$RescueOpCopyWithImpl<$Res>
    implements $RescueOpCopyWith<$Res> {
  _$RescueOpCopyWithImpl(this._self, this._then);

  final RescueOp _self;
  final $Res Function(RescueOp) _then;

/// Create a copy of RescueOp
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? seq = null,}) {
  return _then(_self.copyWith(
seq: null == seq ? _self.seq : seq // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}

}


/// Adds pattern-matching-related methods to [RescueOp].
extension RescueOpPatterns on RescueOp {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( RescueOp_SetRescuer value)?  setRescuer,TResult Function( RescueOp_RotateAdmin value)?  rotateAdmin,required TResult orElse(),}){
final _that = this;
switch (_that) {
case RescueOp_SetRescuer() when setRescuer != null:
return setRescuer(_that);case RescueOp_RotateAdmin() when rotateAdmin != null:
return rotateAdmin(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( RescueOp_SetRescuer value)  setRescuer,required TResult Function( RescueOp_RotateAdmin value)  rotateAdmin,}){
final _that = this;
switch (_that) {
case RescueOp_SetRescuer():
return setRescuer(_that);case RescueOp_RotateAdmin():
return rotateAdmin(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( RescueOp_SetRescuer value)?  setRescuer,TResult? Function( RescueOp_RotateAdmin value)?  rotateAdmin,}){
final _that = this;
switch (_that) {
case RescueOp_SetRescuer() when setRescuer != null:
return setRescuer(_that);case RescueOp_RotateAdmin() when rotateAdmin != null:
return rotateAdmin(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BigInt seq,  String newRescuer)?  setRescuer,TResult Function( BigInt seq,  String newAdmin)?  rotateAdmin,required TResult orElse(),}) {final _that = this;
switch (_that) {
case RescueOp_SetRescuer() when setRescuer != null:
return setRescuer(_that.seq,_that.newRescuer);case RescueOp_RotateAdmin() when rotateAdmin != null:
return rotateAdmin(_that.seq,_that.newAdmin);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BigInt seq,  String newRescuer)  setRescuer,required TResult Function( BigInt seq,  String newAdmin)  rotateAdmin,}) {final _that = this;
switch (_that) {
case RescueOp_SetRescuer():
return setRescuer(_that.seq,_that.newRescuer);case RescueOp_RotateAdmin():
return rotateAdmin(_that.seq,_that.newAdmin);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BigInt seq,  String newRescuer)?  setRescuer,TResult? Function( BigInt seq,  String newAdmin)?  rotateAdmin,}) {final _that = this;
switch (_that) {
case RescueOp_SetRescuer() when setRescuer != null:
return setRescuer(_that.seq,_that.newRescuer);case RescueOp_RotateAdmin() when rotateAdmin != null:
return rotateAdmin(_that.seq,_that.newAdmin);case _:
  return null;

}
}

}

/// @nodoc


class RescueOp_SetRescuer extends RescueOp {
  const RescueOp_SetRescuer({required this.seq, required this.newRescuer}): super._();
  

@override final  BigInt seq;
 final  String newRescuer;

/// Create a copy of RescueOp
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$RescueOp_SetRescuerCopyWith<RescueOp_SetRescuer> get copyWith => _$RescueOp_SetRescuerCopyWithImpl<RescueOp_SetRescuer>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is RescueOp_SetRescuer&&(identical(other.seq, seq) || other.seq == seq)&&(identical(other.newRescuer, newRescuer) || other.newRescuer == newRescuer));
}


@override
int get hashCode => Object.hash(runtimeType,seq,newRescuer);

@override
String toString() {
  return 'RescueOp.setRescuer(seq: $seq, newRescuer: $newRescuer)';
}


}

/// @nodoc
abstract mixin class $RescueOp_SetRescuerCopyWith<$Res> implements $RescueOpCopyWith<$Res> {
  factory $RescueOp_SetRescuerCopyWith(RescueOp_SetRescuer value, $Res Function(RescueOp_SetRescuer) _then) = _$RescueOp_SetRescuerCopyWithImpl;
@override @useResult
$Res call({
 BigInt seq, String newRescuer
});




}
/// @nodoc
class _$RescueOp_SetRescuerCopyWithImpl<$Res>
    implements $RescueOp_SetRescuerCopyWith<$Res> {
  _$RescueOp_SetRescuerCopyWithImpl(this._self, this._then);

  final RescueOp_SetRescuer _self;
  final $Res Function(RescueOp_SetRescuer) _then;

/// Create a copy of RescueOp
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? seq = null,Object? newRescuer = null,}) {
  return _then(RescueOp_SetRescuer(
seq: null == seq ? _self.seq : seq // ignore: cast_nullable_to_non_nullable
as BigInt,newRescuer: null == newRescuer ? _self.newRescuer : newRescuer // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class RescueOp_RotateAdmin extends RescueOp {
  const RescueOp_RotateAdmin({required this.seq, required this.newAdmin}): super._();
  

@override final  BigInt seq;
 final  String newAdmin;

/// Create a copy of RescueOp
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$RescueOp_RotateAdminCopyWith<RescueOp_RotateAdmin> get copyWith => _$RescueOp_RotateAdminCopyWithImpl<RescueOp_RotateAdmin>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is RescueOp_RotateAdmin&&(identical(other.seq, seq) || other.seq == seq)&&(identical(other.newAdmin, newAdmin) || other.newAdmin == newAdmin));
}


@override
int get hashCode => Object.hash(runtimeType,seq,newAdmin);

@override
String toString() {
  return 'RescueOp.rotateAdmin(seq: $seq, newAdmin: $newAdmin)';
}


}

/// @nodoc
abstract mixin class $RescueOp_RotateAdminCopyWith<$Res> implements $RescueOpCopyWith<$Res> {
  factory $RescueOp_RotateAdminCopyWith(RescueOp_RotateAdmin value, $Res Function(RescueOp_RotateAdmin) _then) = _$RescueOp_RotateAdminCopyWithImpl;
@override @useResult
$Res call({
 BigInt seq, String newAdmin
});




}
/// @nodoc
class _$RescueOp_RotateAdminCopyWithImpl<$Res>
    implements $RescueOp_RotateAdminCopyWith<$Res> {
  _$RescueOp_RotateAdminCopyWithImpl(this._self, this._then);

  final RescueOp_RotateAdmin _self;
  final $Res Function(RescueOp_RotateAdmin) _then;

/// Create a copy of RescueOp
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? seq = null,Object? newAdmin = null,}) {
  return _then(RescueOp_RotateAdmin(
seq: null == seq ? _self.seq : seq // ignore: cast_nullable_to_non_nullable
as BigInt,newAdmin: null == newAdmin ? _self.newAdmin : newAdmin // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
