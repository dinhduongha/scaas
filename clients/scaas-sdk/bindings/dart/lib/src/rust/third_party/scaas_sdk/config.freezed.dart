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
mixin _$FamilyParams {

 String get chainId; List<EndpointConfig> get rest; Policy get restPolicy; String get denom; String get prefix;
/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FamilyParamsCopyWith<FamilyParams> get copyWith => _$FamilyParamsCopyWithImpl<FamilyParams>(this as FamilyParams, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FamilyParams&&(identical(other.chainId, chainId) || other.chainId == chainId)&&const DeepCollectionEquality().equals(other.rest, rest)&&(identical(other.restPolicy, restPolicy) || other.restPolicy == restPolicy)&&(identical(other.denom, denom) || other.denom == denom)&&(identical(other.prefix, prefix) || other.prefix == prefix));
}


@override
int get hashCode => Object.hash(runtimeType,chainId,const DeepCollectionEquality().hash(rest),restPolicy,denom,prefix);

@override
String toString() {
  return 'FamilyParams(chainId: $chainId, rest: $rest, restPolicy: $restPolicy, denom: $denom, prefix: $prefix)';
}


}

/// @nodoc
abstract mixin class $FamilyParamsCopyWith<$Res>  {
  factory $FamilyParamsCopyWith(FamilyParams value, $Res Function(FamilyParams) _then) = _$FamilyParamsCopyWithImpl;
@useResult
$Res call({
 String chainId, List<EndpointConfig> rest, Policy restPolicy, String denom, String prefix
});




}
/// @nodoc
class _$FamilyParamsCopyWithImpl<$Res>
    implements $FamilyParamsCopyWith<$Res> {
  _$FamilyParamsCopyWithImpl(this._self, this._then);

  final FamilyParams _self;
  final $Res Function(FamilyParams) _then;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? chainId = null,Object? rest = null,Object? restPolicy = null,Object? denom = null,Object? prefix = null,}) {
  return _then(_self.copyWith(
chainId: null == chainId ? _self.chainId : chainId // ignore: cast_nullable_to_non_nullable
as String,rest: null == rest ? _self.rest : rest // ignore: cast_nullable_to_non_nullable
as List<EndpointConfig>,restPolicy: null == restPolicy ? _self.restPolicy : restPolicy // ignore: cast_nullable_to_non_nullable
as Policy,denom: null == denom ? _self.denom : denom // ignore: cast_nullable_to_non_nullable
as String,prefix: null == prefix ? _self.prefix : prefix // ignore: cast_nullable_to_non_nullable
as String,
  ));
}

}


/// Adds pattern-matching-related methods to [FamilyParams].
extension FamilyParamsPatterns on FamilyParams {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( FamilyParams_Cosmos value)?  cosmos,required TResult orElse(),}){
final _that = this;
switch (_that) {
case FamilyParams_Cosmos() when cosmos != null:
return cosmos(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( FamilyParams_Cosmos value)  cosmos,}){
final _that = this;
switch (_that) {
case FamilyParams_Cosmos():
return cosmos(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( FamilyParams_Cosmos value)?  cosmos,}){
final _that = this;
switch (_that) {
case FamilyParams_Cosmos() when cosmos != null:
return cosmos(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String chainId,  List<EndpointConfig> rest,  Policy restPolicy,  String denom,  String prefix)?  cosmos,required TResult orElse(),}) {final _that = this;
switch (_that) {
case FamilyParams_Cosmos() when cosmos != null:
return cosmos(_that.chainId,_that.rest,_that.restPolicy,_that.denom,_that.prefix);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String chainId,  List<EndpointConfig> rest,  Policy restPolicy,  String denom,  String prefix)  cosmos,}) {final _that = this;
switch (_that) {
case FamilyParams_Cosmos():
return cosmos(_that.chainId,_that.rest,_that.restPolicy,_that.denom,_that.prefix);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String chainId,  List<EndpointConfig> rest,  Policy restPolicy,  String denom,  String prefix)?  cosmos,}) {final _that = this;
switch (_that) {
case FamilyParams_Cosmos() when cosmos != null:
return cosmos(_that.chainId,_that.rest,_that.restPolicy,_that.denom,_that.prefix);case _:
  return null;

}
}

}

/// @nodoc


class FamilyParams_Cosmos extends FamilyParams {
  const FamilyParams_Cosmos({required this.chainId, required final  List<EndpointConfig> rest, required this.restPolicy, required this.denom, required this.prefix}): _rest = rest,super._();
  

@override final  String chainId;
 final  List<EndpointConfig> _rest;
@override List<EndpointConfig> get rest {
  if (_rest is EqualUnmodifiableListView) return _rest;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_rest);
}

@override final  Policy restPolicy;
@override final  String denom;
@override final  String prefix;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FamilyParams_CosmosCopyWith<FamilyParams_Cosmos> get copyWith => _$FamilyParams_CosmosCopyWithImpl<FamilyParams_Cosmos>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FamilyParams_Cosmos&&(identical(other.chainId, chainId) || other.chainId == chainId)&&const DeepCollectionEquality().equals(other._rest, _rest)&&(identical(other.restPolicy, restPolicy) || other.restPolicy == restPolicy)&&(identical(other.denom, denom) || other.denom == denom)&&(identical(other.prefix, prefix) || other.prefix == prefix));
}


@override
int get hashCode => Object.hash(runtimeType,chainId,const DeepCollectionEquality().hash(_rest),restPolicy,denom,prefix);

@override
String toString() {
  return 'FamilyParams.cosmos(chainId: $chainId, rest: $rest, restPolicy: $restPolicy, denom: $denom, prefix: $prefix)';
}


}

/// @nodoc
abstract mixin class $FamilyParams_CosmosCopyWith<$Res> implements $FamilyParamsCopyWith<$Res> {
  factory $FamilyParams_CosmosCopyWith(FamilyParams_Cosmos value, $Res Function(FamilyParams_Cosmos) _then) = _$FamilyParams_CosmosCopyWithImpl;
@override @useResult
$Res call({
 String chainId, List<EndpointConfig> rest, Policy restPolicy, String denom, String prefix
});




}
/// @nodoc
class _$FamilyParams_CosmosCopyWithImpl<$Res>
    implements $FamilyParams_CosmosCopyWith<$Res> {
  _$FamilyParams_CosmosCopyWithImpl(this._self, this._then);

  final FamilyParams_Cosmos _self;
  final $Res Function(FamilyParams_Cosmos) _then;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? chainId = null,Object? rest = null,Object? restPolicy = null,Object? denom = null,Object? prefix = null,}) {
  return _then(FamilyParams_Cosmos(
chainId: null == chainId ? _self.chainId : chainId // ignore: cast_nullable_to_non_nullable
as String,rest: null == rest ? _self._rest : rest // ignore: cast_nullable_to_non_nullable
as List<EndpointConfig>,restPolicy: null == restPolicy ? _self.restPolicy : restPolicy // ignore: cast_nullable_to_non_nullable
as Policy,denom: null == denom ? _self.denom : denom // ignore: cast_nullable_to_non_nullable
as String,prefix: null == prefix ? _self.prefix : prefix // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

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
