// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'config.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$Finality {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Finality);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'Finality()';
}


}

/// @nodoc
class $FinalityCopyWith<$Res>  {
$FinalityCopyWith(Finality _, $Res Function(Finality) __);
}


/// Adds pattern-matching-related methods to [Finality].
extension FinalityPatterns on Finality {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( Finality_Finalized value)?  finalized,TResult Function( Finality_Depth value)?  depth,required TResult orElse(),}){
final _that = this;
switch (_that) {
case Finality_Finalized() when finalized != null:
return finalized(_that);case Finality_Depth() when depth != null:
return depth(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( Finality_Finalized value)  finalized,required TResult Function( Finality_Depth value)  depth,}){
final _that = this;
switch (_that) {
case Finality_Finalized():
return finalized(_that);case Finality_Depth():
return depth(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( Finality_Finalized value)?  finalized,TResult? Function( Finality_Depth value)?  depth,}){
final _that = this;
switch (_that) {
case Finality_Finalized() when finalized != null:
return finalized(_that);case Finality_Depth() when depth != null:
return depth(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  finalized,TResult Function( BigInt field0)?  depth,required TResult orElse(),}) {final _that = this;
switch (_that) {
case Finality_Finalized() when finalized != null:
return finalized();case Finality_Depth() when depth != null:
return depth(_that.field0);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  finalized,required TResult Function( BigInt field0)  depth,}) {final _that = this;
switch (_that) {
case Finality_Finalized():
return finalized();case Finality_Depth():
return depth(_that.field0);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  finalized,TResult? Function( BigInt field0)?  depth,}) {final _that = this;
switch (_that) {
case Finality_Finalized() when finalized != null:
return finalized();case Finality_Depth() when depth != null:
return depth(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class Finality_Finalized extends Finality {
  const Finality_Finalized(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Finality_Finalized);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'Finality.finalized()';
}


}




/// @nodoc


class Finality_Depth extends Finality {
  const Finality_Depth(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of Finality
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Finality_DepthCopyWith<Finality_Depth> get copyWith => _$Finality_DepthCopyWithImpl<Finality_Depth>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Finality_Depth&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'Finality.depth(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $Finality_DepthCopyWith<$Res> implements $FinalityCopyWith<$Res> {
  factory $Finality_DepthCopyWith(Finality_Depth value, $Res Function(Finality_Depth) _then) = _$Finality_DepthCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$Finality_DepthCopyWithImpl<$Res>
    implements $Finality_DepthCopyWith<$Res> {
  _$Finality_DepthCopyWithImpl(this._self, this._then);

  final Finality_Depth _self;
  final $Res Function(Finality_Depth) _then;

/// Create a copy of Finality
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(Finality_Depth(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

// dart format on
