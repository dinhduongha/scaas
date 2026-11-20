// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'delay.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$DelaySentence {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is DelaySentence);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'DelaySentence()';
}


}

/// @nodoc
class $DelaySentenceCopyWith<$Res>  {
$DelaySentenceCopyWith(DelaySentence _, $Res Function(DelaySentence) __);
}


/// Adds pattern-matching-related methods to [DelaySentence].
extension DelaySentencePatterns on DelaySentence {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( DelaySentence_AtOnce value)?  atOnce,TResult Function( DelaySentence_After value)?  after,TResult Function( DelaySentence_SingleKey value)?  singleKey,TResult Function( DelaySentence_Locked value)?  locked,TResult Function( DelaySentence_NoDelay value)?  noDelay,TResult Function( DelaySentence_Unknown value)?  unknown,required TResult orElse(),}){
final _that = this;
switch (_that) {
case DelaySentence_AtOnce() when atOnce != null:
return atOnce(_that);case DelaySentence_After() when after != null:
return after(_that);case DelaySentence_SingleKey() when singleKey != null:
return singleKey(_that);case DelaySentence_Locked() when locked != null:
return locked(_that);case DelaySentence_NoDelay() when noDelay != null:
return noDelay(_that);case DelaySentence_Unknown() when unknown != null:
return unknown(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( DelaySentence_AtOnce value)  atOnce,required TResult Function( DelaySentence_After value)  after,required TResult Function( DelaySentence_SingleKey value)  singleKey,required TResult Function( DelaySentence_Locked value)  locked,required TResult Function( DelaySentence_NoDelay value)  noDelay,required TResult Function( DelaySentence_Unknown value)  unknown,}){
final _that = this;
switch (_that) {
case DelaySentence_AtOnce():
return atOnce(_that);case DelaySentence_After():
return after(_that);case DelaySentence_SingleKey():
return singleKey(_that);case DelaySentence_Locked():
return locked(_that);case DelaySentence_NoDelay():
return noDelay(_that);case DelaySentence_Unknown():
return unknown(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( DelaySentence_AtOnce value)?  atOnce,TResult? Function( DelaySentence_After value)?  after,TResult? Function( DelaySentence_SingleKey value)?  singleKey,TResult? Function( DelaySentence_Locked value)?  locked,TResult? Function( DelaySentence_NoDelay value)?  noDelay,TResult? Function( DelaySentence_Unknown value)?  unknown,}){
final _that = this;
switch (_that) {
case DelaySentence_AtOnce() when atOnce != null:
return atOnce(_that);case DelaySentence_After() when after != null:
return after(_that);case DelaySentence_SingleKey() when singleKey != null:
return singleKey(_that);case DelaySentence_Locked() when locked != null:
return locked(_that);case DelaySentence_NoDelay() when noDelay != null:
return noDelay(_that);case DelaySentence_Unknown() when unknown != null:
return unknown(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  atOnce,TResult Function( BigInt delay)?  after,TResult Function()?  singleKey,TResult Function()?  locked,TResult Function()?  noDelay,TResult Function()?  unknown,required TResult orElse(),}) {final _that = this;
switch (_that) {
case DelaySentence_AtOnce() when atOnce != null:
return atOnce();case DelaySentence_After() when after != null:
return after(_that.delay);case DelaySentence_SingleKey() when singleKey != null:
return singleKey();case DelaySentence_Locked() when locked != null:
return locked();case DelaySentence_NoDelay() when noDelay != null:
return noDelay();case DelaySentence_Unknown() when unknown != null:
return unknown();case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  atOnce,required TResult Function( BigInt delay)  after,required TResult Function()  singleKey,required TResult Function()  locked,required TResult Function()  noDelay,required TResult Function()  unknown,}) {final _that = this;
switch (_that) {
case DelaySentence_AtOnce():
return atOnce();case DelaySentence_After():
return after(_that.delay);case DelaySentence_SingleKey():
return singleKey();case DelaySentence_Locked():
return locked();case DelaySentence_NoDelay():
return noDelay();case DelaySentence_Unknown():
return unknown();}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  atOnce,TResult? Function( BigInt delay)?  after,TResult? Function()?  singleKey,TResult? Function()?  locked,TResult? Function()?  noDelay,TResult? Function()?  unknown,}) {final _that = this;
switch (_that) {
case DelaySentence_AtOnce() when atOnce != null:
return atOnce();case DelaySentence_After() when after != null:
return after(_that.delay);case DelaySentence_SingleKey() when singleKey != null:
return singleKey();case DelaySentence_Locked() when locked != null:
return locked();case DelaySentence_NoDelay() when noDelay != null:
return noDelay();case DelaySentence_Unknown() when unknown != null:
return unknown();case _:
  return null;

}
}

}

/// @nodoc


class DelaySentence_AtOnce extends DelaySentence {
  const DelaySentence_AtOnce(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is DelaySentence_AtOnce);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'DelaySentence.atOnce()';
}


}




/// @nodoc


class DelaySentence_After extends DelaySentence {
  const DelaySentence_After({required this.delay}): super._();
  

 final  BigInt delay;

/// Create a copy of DelaySentence
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$DelaySentence_AfterCopyWith<DelaySentence_After> get copyWith => _$DelaySentence_AfterCopyWithImpl<DelaySentence_After>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is DelaySentence_After&&(identical(other.delay, delay) || other.delay == delay));
}


@override
int get hashCode => Object.hash(runtimeType,delay);

@override
String toString() {
  return 'DelaySentence.after(delay: $delay)';
}


}

/// @nodoc
abstract mixin class $DelaySentence_AfterCopyWith<$Res> implements $DelaySentenceCopyWith<$Res> {
  factory $DelaySentence_AfterCopyWith(DelaySentence_After value, $Res Function(DelaySentence_After) _then) = _$DelaySentence_AfterCopyWithImpl;
@useResult
$Res call({
 BigInt delay
});




}
/// @nodoc
class _$DelaySentence_AfterCopyWithImpl<$Res>
    implements $DelaySentence_AfterCopyWith<$Res> {
  _$DelaySentence_AfterCopyWithImpl(this._self, this._then);

  final DelaySentence_After _self;
  final $Res Function(DelaySentence_After) _then;

/// Create a copy of DelaySentence
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? delay = null,}) {
  return _then(DelaySentence_After(
delay: null == delay ? _self.delay : delay // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class DelaySentence_SingleKey extends DelaySentence {
  const DelaySentence_SingleKey(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is DelaySentence_SingleKey);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'DelaySentence.singleKey()';
}


}




/// @nodoc


class DelaySentence_Locked extends DelaySentence {
  const DelaySentence_Locked(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is DelaySentence_Locked);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'DelaySentence.locked()';
}


}




/// @nodoc


class DelaySentence_NoDelay extends DelaySentence {
  const DelaySentence_NoDelay(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is DelaySentence_NoDelay);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'DelaySentence.noDelay()';
}


}




/// @nodoc


class DelaySentence_Unknown extends DelaySentence {
  const DelaySentence_Unknown(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is DelaySentence_Unknown);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'DelaySentence.unknown()';
}


}




// dart format on
