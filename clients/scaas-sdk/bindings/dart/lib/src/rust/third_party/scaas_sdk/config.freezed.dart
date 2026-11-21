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





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FamilyParams);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'FamilyParams()';
}


}

/// @nodoc
class $FamilyParamsCopyWith<$Res>  {
$FamilyParamsCopyWith(FamilyParams _, $Res Function(FamilyParams) __);
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( FamilyParams_Cosmos value)?  cosmos,TResult Function( FamilyParams_Aptos value)?  aptos,TResult Function( FamilyParams_Solana value)?  solana,TResult Function( FamilyParams_Soroban value)?  soroban,TResult Function( FamilyParams_Sui value)?  sui,required TResult orElse(),}){
final _that = this;
switch (_that) {
case FamilyParams_Cosmos() when cosmos != null:
return cosmos(_that);case FamilyParams_Aptos() when aptos != null:
return aptos(_that);case FamilyParams_Solana() when solana != null:
return solana(_that);case FamilyParams_Soroban() when soroban != null:
return soroban(_that);case FamilyParams_Sui() when sui != null:
return sui(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( FamilyParams_Cosmos value)  cosmos,required TResult Function( FamilyParams_Aptos value)  aptos,required TResult Function( FamilyParams_Solana value)  solana,required TResult Function( FamilyParams_Soroban value)  soroban,required TResult Function( FamilyParams_Sui value)  sui,}){
final _that = this;
switch (_that) {
case FamilyParams_Cosmos():
return cosmos(_that);case FamilyParams_Aptos():
return aptos(_that);case FamilyParams_Solana():
return solana(_that);case FamilyParams_Soroban():
return soroban(_that);case FamilyParams_Sui():
return sui(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( FamilyParams_Cosmos value)?  cosmos,TResult? Function( FamilyParams_Aptos value)?  aptos,TResult? Function( FamilyParams_Solana value)?  solana,TResult? Function( FamilyParams_Soroban value)?  soroban,TResult? Function( FamilyParams_Sui value)?  sui,}){
final _that = this;
switch (_that) {
case FamilyParams_Cosmos() when cosmos != null:
return cosmos(_that);case FamilyParams_Aptos() when aptos != null:
return aptos(_that);case FamilyParams_Solana() when solana != null:
return solana(_that);case FamilyParams_Soroban() when soroban != null:
return soroban(_that);case FamilyParams_Sui() when sui != null:
return sui(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String chainId,  List<EndpointConfig> rest,  Policy restPolicy,  String denom,  String prefix)?  cosmos,TResult Function( int chainId,  String package)?  aptos,TResult Function( String program)?  solana,TResult Function( String passphrase,  String xlmSac)?  soroban,TResult Function( List<EndpointConfig> graphql,  Policy graphqlPolicy)?  sui,required TResult orElse(),}) {final _that = this;
switch (_that) {
case FamilyParams_Cosmos() when cosmos != null:
return cosmos(_that.chainId,_that.rest,_that.restPolicy,_that.denom,_that.prefix);case FamilyParams_Aptos() when aptos != null:
return aptos(_that.chainId,_that.package);case FamilyParams_Solana() when solana != null:
return solana(_that.program);case FamilyParams_Soroban() when soroban != null:
return soroban(_that.passphrase,_that.xlmSac);case FamilyParams_Sui() when sui != null:
return sui(_that.graphql,_that.graphqlPolicy);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String chainId,  List<EndpointConfig> rest,  Policy restPolicy,  String denom,  String prefix)  cosmos,required TResult Function( int chainId,  String package)  aptos,required TResult Function( String program)  solana,required TResult Function( String passphrase,  String xlmSac)  soroban,required TResult Function( List<EndpointConfig> graphql,  Policy graphqlPolicy)  sui,}) {final _that = this;
switch (_that) {
case FamilyParams_Cosmos():
return cosmos(_that.chainId,_that.rest,_that.restPolicy,_that.denom,_that.prefix);case FamilyParams_Aptos():
return aptos(_that.chainId,_that.package);case FamilyParams_Solana():
return solana(_that.program);case FamilyParams_Soroban():
return soroban(_that.passphrase,_that.xlmSac);case FamilyParams_Sui():
return sui(_that.graphql,_that.graphqlPolicy);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String chainId,  List<EndpointConfig> rest,  Policy restPolicy,  String denom,  String prefix)?  cosmos,TResult? Function( int chainId,  String package)?  aptos,TResult? Function( String program)?  solana,TResult? Function( String passphrase,  String xlmSac)?  soroban,TResult? Function( List<EndpointConfig> graphql,  Policy graphqlPolicy)?  sui,}) {final _that = this;
switch (_that) {
case FamilyParams_Cosmos() when cosmos != null:
return cosmos(_that.chainId,_that.rest,_that.restPolicy,_that.denom,_that.prefix);case FamilyParams_Aptos() when aptos != null:
return aptos(_that.chainId,_that.package);case FamilyParams_Solana() when solana != null:
return solana(_that.program);case FamilyParams_Soroban() when soroban != null:
return soroban(_that.passphrase,_that.xlmSac);case FamilyParams_Sui() when sui != null:
return sui(_that.graphql,_that.graphqlPolicy);case _:
  return null;

}
}

}

/// @nodoc


class FamilyParams_Cosmos extends FamilyParams {
  const FamilyParams_Cosmos({required this.chainId, required final  List<EndpointConfig> rest, required this.restPolicy, required this.denom, required this.prefix}): _rest = rest,super._();
  

 final  String chainId;
 final  List<EndpointConfig> _rest;
 List<EndpointConfig> get rest {
  if (_rest is EqualUnmodifiableListView) return _rest;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_rest);
}

 final  Policy restPolicy;
 final  String denom;
 final  String prefix;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
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
@useResult
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
@pragma('vm:prefer-inline') $Res call({Object? chainId = null,Object? rest = null,Object? restPolicy = null,Object? denom = null,Object? prefix = null,}) {
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


class FamilyParams_Aptos extends FamilyParams {
  const FamilyParams_Aptos({required this.chainId, required this.package}): super._();
  

 final  int chainId;
 final  String package;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FamilyParams_AptosCopyWith<FamilyParams_Aptos> get copyWith => _$FamilyParams_AptosCopyWithImpl<FamilyParams_Aptos>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FamilyParams_Aptos&&(identical(other.chainId, chainId) || other.chainId == chainId)&&(identical(other.package, package) || other.package == package));
}


@override
int get hashCode => Object.hash(runtimeType,chainId,package);

@override
String toString() {
  return 'FamilyParams.aptos(chainId: $chainId, package: $package)';
}


}

/// @nodoc
abstract mixin class $FamilyParams_AptosCopyWith<$Res> implements $FamilyParamsCopyWith<$Res> {
  factory $FamilyParams_AptosCopyWith(FamilyParams_Aptos value, $Res Function(FamilyParams_Aptos) _then) = _$FamilyParams_AptosCopyWithImpl;
@useResult
$Res call({
 int chainId, String package
});




}
/// @nodoc
class _$FamilyParams_AptosCopyWithImpl<$Res>
    implements $FamilyParams_AptosCopyWith<$Res> {
  _$FamilyParams_AptosCopyWithImpl(this._self, this._then);

  final FamilyParams_Aptos _self;
  final $Res Function(FamilyParams_Aptos) _then;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? chainId = null,Object? package = null,}) {
  return _then(FamilyParams_Aptos(
chainId: null == chainId ? _self.chainId : chainId // ignore: cast_nullable_to_non_nullable
as int,package: null == package ? _self.package : package // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FamilyParams_Solana extends FamilyParams {
  const FamilyParams_Solana({required this.program}): super._();
  

 final  String program;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FamilyParams_SolanaCopyWith<FamilyParams_Solana> get copyWith => _$FamilyParams_SolanaCopyWithImpl<FamilyParams_Solana>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FamilyParams_Solana&&(identical(other.program, program) || other.program == program));
}


@override
int get hashCode => Object.hash(runtimeType,program);

@override
String toString() {
  return 'FamilyParams.solana(program: $program)';
}


}

/// @nodoc
abstract mixin class $FamilyParams_SolanaCopyWith<$Res> implements $FamilyParamsCopyWith<$Res> {
  factory $FamilyParams_SolanaCopyWith(FamilyParams_Solana value, $Res Function(FamilyParams_Solana) _then) = _$FamilyParams_SolanaCopyWithImpl;
@useResult
$Res call({
 String program
});




}
/// @nodoc
class _$FamilyParams_SolanaCopyWithImpl<$Res>
    implements $FamilyParams_SolanaCopyWith<$Res> {
  _$FamilyParams_SolanaCopyWithImpl(this._self, this._then);

  final FamilyParams_Solana _self;
  final $Res Function(FamilyParams_Solana) _then;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? program = null,}) {
  return _then(FamilyParams_Solana(
program: null == program ? _self.program : program // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FamilyParams_Soroban extends FamilyParams {
  const FamilyParams_Soroban({required this.passphrase, required this.xlmSac}): super._();
  

 final  String passphrase;
 final  String xlmSac;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FamilyParams_SorobanCopyWith<FamilyParams_Soroban> get copyWith => _$FamilyParams_SorobanCopyWithImpl<FamilyParams_Soroban>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FamilyParams_Soroban&&(identical(other.passphrase, passphrase) || other.passphrase == passphrase)&&(identical(other.xlmSac, xlmSac) || other.xlmSac == xlmSac));
}


@override
int get hashCode => Object.hash(runtimeType,passphrase,xlmSac);

@override
String toString() {
  return 'FamilyParams.soroban(passphrase: $passphrase, xlmSac: $xlmSac)';
}


}

/// @nodoc
abstract mixin class $FamilyParams_SorobanCopyWith<$Res> implements $FamilyParamsCopyWith<$Res> {
  factory $FamilyParams_SorobanCopyWith(FamilyParams_Soroban value, $Res Function(FamilyParams_Soroban) _then) = _$FamilyParams_SorobanCopyWithImpl;
@useResult
$Res call({
 String passphrase, String xlmSac
});




}
/// @nodoc
class _$FamilyParams_SorobanCopyWithImpl<$Res>
    implements $FamilyParams_SorobanCopyWith<$Res> {
  _$FamilyParams_SorobanCopyWithImpl(this._self, this._then);

  final FamilyParams_Soroban _self;
  final $Res Function(FamilyParams_Soroban) _then;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? passphrase = null,Object? xlmSac = null,}) {
  return _then(FamilyParams_Soroban(
passphrase: null == passphrase ? _self.passphrase : passphrase // ignore: cast_nullable_to_non_nullable
as String,xlmSac: null == xlmSac ? _self.xlmSac : xlmSac // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class FamilyParams_Sui extends FamilyParams {
  const FamilyParams_Sui({required final  List<EndpointConfig> graphql, required this.graphqlPolicy}): _graphql = graphql,super._();
  

 final  List<EndpointConfig> _graphql;
 List<EndpointConfig> get graphql {
  if (_graphql is EqualUnmodifiableListView) return _graphql;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_graphql);
}

 final  Policy graphqlPolicy;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$FamilyParams_SuiCopyWith<FamilyParams_Sui> get copyWith => _$FamilyParams_SuiCopyWithImpl<FamilyParams_Sui>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is FamilyParams_Sui&&const DeepCollectionEquality().equals(other._graphql, _graphql)&&(identical(other.graphqlPolicy, graphqlPolicy) || other.graphqlPolicy == graphqlPolicy));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(_graphql),graphqlPolicy);

@override
String toString() {
  return 'FamilyParams.sui(graphql: $graphql, graphqlPolicy: $graphqlPolicy)';
}


}

/// @nodoc
abstract mixin class $FamilyParams_SuiCopyWith<$Res> implements $FamilyParamsCopyWith<$Res> {
  factory $FamilyParams_SuiCopyWith(FamilyParams_Sui value, $Res Function(FamilyParams_Sui) _then) = _$FamilyParams_SuiCopyWithImpl;
@useResult
$Res call({
 List<EndpointConfig> graphql, Policy graphqlPolicy
});




}
/// @nodoc
class _$FamilyParams_SuiCopyWithImpl<$Res>
    implements $FamilyParams_SuiCopyWith<$Res> {
  _$FamilyParams_SuiCopyWithImpl(this._self, this._then);

  final FamilyParams_Sui _self;
  final $Res Function(FamilyParams_Sui) _then;

/// Create a copy of FamilyParams
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? graphql = null,Object? graphqlPolicy = null,}) {
  return _then(FamilyParams_Sui(
graphql: null == graphql ? _self._graphql : graphql // ignore: cast_nullable_to_non_nullable
as List<EndpointConfig>,graphqlPolicy: null == graphqlPolicy ? _self.graphqlPolicy : graphqlPolicy // ignore: cast_nullable_to_non_nullable
as Policy,
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
