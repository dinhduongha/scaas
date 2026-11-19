// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'op.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$GasFrom {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is GasFrom);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'GasFrom()';
}


}

/// @nodoc
class $GasFromCopyWith<$Res>  {
$GasFromCopyWith(GasFrom _, $Res Function(GasFrom) __);
}


/// Adds pattern-matching-related methods to [GasFrom].
extension GasFromPatterns on GasFrom {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( GasFrom_Chain value)?  chain,TResult Function( GasFrom_Module value)?  module,TResult Function( GasFrom_Reference value)?  reference,TResult Function( GasFrom_App value)?  app,TResult Function( GasFrom_Estimate value)?  estimate,required TResult orElse(),}){
final _that = this;
switch (_that) {
case GasFrom_Chain() when chain != null:
return chain(_that);case GasFrom_Module() when module != null:
return module(_that);case GasFrom_Reference() when reference != null:
return reference(_that);case GasFrom_App() when app != null:
return app(_that);case GasFrom_Estimate() when estimate != null:
return estimate(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( GasFrom_Chain value)  chain,required TResult Function( GasFrom_Module value)  module,required TResult Function( GasFrom_Reference value)  reference,required TResult Function( GasFrom_App value)  app,required TResult Function( GasFrom_Estimate value)  estimate,}){
final _that = this;
switch (_that) {
case GasFrom_Chain():
return chain(_that);case GasFrom_Module():
return module(_that);case GasFrom_Reference():
return reference(_that);case GasFrom_App():
return app(_that);case GasFrom_Estimate():
return estimate(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( GasFrom_Chain value)?  chain,TResult? Function( GasFrom_Module value)?  module,TResult? Function( GasFrom_Reference value)?  reference,TResult? Function( GasFrom_App value)?  app,TResult? Function( GasFrom_Estimate value)?  estimate,}){
final _that = this;
switch (_that) {
case GasFrom_Chain() when chain != null:
return chain(_that);case GasFrom_Module() when module != null:
return module(_that);case GasFrom_Reference() when reference != null:
return reference(_that);case GasFrom_App() when app != null:
return app(_that);case GasFrom_Estimate() when estimate != null:
return estimate(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  chain,TResult Function( String field0)?  module,TResult Function()?  reference,TResult Function()?  app,TResult Function()?  estimate,required TResult orElse(),}) {final _that = this;
switch (_that) {
case GasFrom_Chain() when chain != null:
return chain();case GasFrom_Module() when module != null:
return module(_that.field0);case GasFrom_Reference() when reference != null:
return reference();case GasFrom_App() when app != null:
return app();case GasFrom_Estimate() when estimate != null:
return estimate();case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  chain,required TResult Function( String field0)  module,required TResult Function()  reference,required TResult Function()  app,required TResult Function()  estimate,}) {final _that = this;
switch (_that) {
case GasFrom_Chain():
return chain();case GasFrom_Module():
return module(_that.field0);case GasFrom_Reference():
return reference();case GasFrom_App():
return app();case GasFrom_Estimate():
return estimate();}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  chain,TResult? Function( String field0)?  module,TResult? Function()?  reference,TResult? Function()?  app,TResult? Function()?  estimate,}) {final _that = this;
switch (_that) {
case GasFrom_Chain() when chain != null:
return chain();case GasFrom_Module() when module != null:
return module(_that.field0);case GasFrom_Reference() when reference != null:
return reference();case GasFrom_App() when app != null:
return app();case GasFrom_Estimate() when estimate != null:
return estimate();case _:
  return null;

}
}

}

/// @nodoc


class GasFrom_Chain extends GasFrom {
  const GasFrom_Chain(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is GasFrom_Chain);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'GasFrom.chain()';
}


}




/// @nodoc


class GasFrom_Module extends GasFrom {
  const GasFrom_Module(this.field0): super._();
  

 final  String field0;

/// Create a copy of GasFrom
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$GasFrom_ModuleCopyWith<GasFrom_Module> get copyWith => _$GasFrom_ModuleCopyWithImpl<GasFrom_Module>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is GasFrom_Module&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'GasFrom.module(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $GasFrom_ModuleCopyWith<$Res> implements $GasFromCopyWith<$Res> {
  factory $GasFrom_ModuleCopyWith(GasFrom_Module value, $Res Function(GasFrom_Module) _then) = _$GasFrom_ModuleCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$GasFrom_ModuleCopyWithImpl<$Res>
    implements $GasFrom_ModuleCopyWith<$Res> {
  _$GasFrom_ModuleCopyWithImpl(this._self, this._then);

  final GasFrom_Module _self;
  final $Res Function(GasFrom_Module) _then;

/// Create a copy of GasFrom
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(GasFrom_Module(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class GasFrom_Reference extends GasFrom {
  const GasFrom_Reference(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is GasFrom_Reference);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'GasFrom.reference()';
}


}




/// @nodoc


class GasFrom_App extends GasFrom {
  const GasFrom_App(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is GasFrom_App);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'GasFrom.app()';
}


}




/// @nodoc


class GasFrom_Estimate extends GasFrom {
  const GasFrom_Estimate(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is GasFrom_Estimate);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'GasFrom.estimate()';
}


}




/// @nodoc
mixin _$KeyRef {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KeyRef);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'KeyRef()';
}


}

/// @nodoc
class $KeyRefCopyWith<$Res>  {
$KeyRefCopyWith(KeyRef _, $Res Function(KeyRef) __);
}


/// Adds pattern-matching-related methods to [KeyRef].
extension KeyRefPatterns on KeyRef {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( KeyRef_Ua value)?  ua,TResult Function( KeyRef_Native value)?  native,TResult Function( KeyRef_Imported value)?  imported,TResult Function( KeyRef_Key value)?  key,TResult Function( KeyRef_Msig value)?  msig,required TResult orElse(),}){
final _that = this;
switch (_that) {
case KeyRef_Ua() when ua != null:
return ua(_that);case KeyRef_Native() when native != null:
return native(_that);case KeyRef_Imported() when imported != null:
return imported(_that);case KeyRef_Key() when key != null:
return key(_that);case KeyRef_Msig() when msig != null:
return msig(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( KeyRef_Ua value)  ua,required TResult Function( KeyRef_Native value)  native,required TResult Function( KeyRef_Imported value)  imported,required TResult Function( KeyRef_Key value)  key,required TResult Function( KeyRef_Msig value)  msig,}){
final _that = this;
switch (_that) {
case KeyRef_Ua():
return ua(_that);case KeyRef_Native():
return native(_that);case KeyRef_Imported():
return imported(_that);case KeyRef_Key():
return key(_that);case KeyRef_Msig():
return msig(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( KeyRef_Ua value)?  ua,TResult? Function( KeyRef_Native value)?  native,TResult? Function( KeyRef_Imported value)?  imported,TResult? Function( KeyRef_Key value)?  key,TResult? Function( KeyRef_Msig value)?  msig,}){
final _that = this;
switch (_that) {
case KeyRef_Ua() when ua != null:
return ua(_that);case KeyRef_Native() when native != null:
return native(_that);case KeyRef_Imported() when imported != null:
return imported(_that);case KeyRef_Key() when key != null:
return key(_that);case KeyRef_Msig() when msig != null:
return msig(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String seed,  int kind,  int account,  int index)?  ua,TResult Function( String seed,  String network,  int index)?  native,TResult Function( String seed,  String network,  int index)?  imported,TResult Function( String seed,  String id)?  key,TResult Function( String ua,  List<MsigSlot> slots)?  msig,required TResult orElse(),}) {final _that = this;
switch (_that) {
case KeyRef_Ua() when ua != null:
return ua(_that.seed,_that.kind,_that.account,_that.index);case KeyRef_Native() when native != null:
return native(_that.seed,_that.network,_that.index);case KeyRef_Imported() when imported != null:
return imported(_that.seed,_that.network,_that.index);case KeyRef_Key() when key != null:
return key(_that.seed,_that.id);case KeyRef_Msig() when msig != null:
return msig(_that.ua,_that.slots);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String seed,  int kind,  int account,  int index)  ua,required TResult Function( String seed,  String network,  int index)  native,required TResult Function( String seed,  String network,  int index)  imported,required TResult Function( String seed,  String id)  key,required TResult Function( String ua,  List<MsigSlot> slots)  msig,}) {final _that = this;
switch (_that) {
case KeyRef_Ua():
return ua(_that.seed,_that.kind,_that.account,_that.index);case KeyRef_Native():
return native(_that.seed,_that.network,_that.index);case KeyRef_Imported():
return imported(_that.seed,_that.network,_that.index);case KeyRef_Key():
return key(_that.seed,_that.id);case KeyRef_Msig():
return msig(_that.ua,_that.slots);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String seed,  int kind,  int account,  int index)?  ua,TResult? Function( String seed,  String network,  int index)?  native,TResult? Function( String seed,  String network,  int index)?  imported,TResult? Function( String seed,  String id)?  key,TResult? Function( String ua,  List<MsigSlot> slots)?  msig,}) {final _that = this;
switch (_that) {
case KeyRef_Ua() when ua != null:
return ua(_that.seed,_that.kind,_that.account,_that.index);case KeyRef_Native() when native != null:
return native(_that.seed,_that.network,_that.index);case KeyRef_Imported() when imported != null:
return imported(_that.seed,_that.network,_that.index);case KeyRef_Key() when key != null:
return key(_that.seed,_that.id);case KeyRef_Msig() when msig != null:
return msig(_that.ua,_that.slots);case _:
  return null;

}
}

}

/// @nodoc


class KeyRef_Ua extends KeyRef {
  const KeyRef_Ua({required this.seed, required this.kind, required this.account, required this.index}): super._();
  

 final  String seed;
 final  int kind;
 final  int account;
 final  int index;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KeyRef_UaCopyWith<KeyRef_Ua> get copyWith => _$KeyRef_UaCopyWithImpl<KeyRef_Ua>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KeyRef_Ua&&(identical(other.seed, seed) || other.seed == seed)&&(identical(other.kind, kind) || other.kind == kind)&&(identical(other.account, account) || other.account == account)&&(identical(other.index, index) || other.index == index));
}


@override
int get hashCode => Object.hash(runtimeType,seed,kind,account,index);

@override
String toString() {
  return 'KeyRef.ua(seed: $seed, kind: $kind, account: $account, index: $index)';
}


}

/// @nodoc
abstract mixin class $KeyRef_UaCopyWith<$Res> implements $KeyRefCopyWith<$Res> {
  factory $KeyRef_UaCopyWith(KeyRef_Ua value, $Res Function(KeyRef_Ua) _then) = _$KeyRef_UaCopyWithImpl;
@useResult
$Res call({
 String seed, int kind, int account, int index
});




}
/// @nodoc
class _$KeyRef_UaCopyWithImpl<$Res>
    implements $KeyRef_UaCopyWith<$Res> {
  _$KeyRef_UaCopyWithImpl(this._self, this._then);

  final KeyRef_Ua _self;
  final $Res Function(KeyRef_Ua) _then;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? seed = null,Object? kind = null,Object? account = null,Object? index = null,}) {
  return _then(KeyRef_Ua(
seed: null == seed ? _self.seed : seed // ignore: cast_nullable_to_non_nullable
as String,kind: null == kind ? _self.kind : kind // ignore: cast_nullable_to_non_nullable
as int,account: null == account ? _self.account : account // ignore: cast_nullable_to_non_nullable
as int,index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as int,
  ));
}


}

/// @nodoc


class KeyRef_Native extends KeyRef {
  const KeyRef_Native({required this.seed, required this.network, required this.index}): super._();
  

 final  String seed;
/// a `scaas-ua` network name (`evm` for a payer)
 final  String network;
 final  int index;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KeyRef_NativeCopyWith<KeyRef_Native> get copyWith => _$KeyRef_NativeCopyWithImpl<KeyRef_Native>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KeyRef_Native&&(identical(other.seed, seed) || other.seed == seed)&&(identical(other.network, network) || other.network == network)&&(identical(other.index, index) || other.index == index));
}


@override
int get hashCode => Object.hash(runtimeType,seed,network,index);

@override
String toString() {
  return 'KeyRef.native(seed: $seed, network: $network, index: $index)';
}


}

/// @nodoc
abstract mixin class $KeyRef_NativeCopyWith<$Res> implements $KeyRefCopyWith<$Res> {
  factory $KeyRef_NativeCopyWith(KeyRef_Native value, $Res Function(KeyRef_Native) _then) = _$KeyRef_NativeCopyWithImpl;
@useResult
$Res call({
 String seed, String network, int index
});




}
/// @nodoc
class _$KeyRef_NativeCopyWithImpl<$Res>
    implements $KeyRef_NativeCopyWith<$Res> {
  _$KeyRef_NativeCopyWithImpl(this._self, this._then);

  final KeyRef_Native _self;
  final $Res Function(KeyRef_Native) _then;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? seed = null,Object? network = null,Object? index = null,}) {
  return _then(KeyRef_Native(
seed: null == seed ? _self.seed : seed // ignore: cast_nullable_to_non_nullable
as String,network: null == network ? _self.network : network // ignore: cast_nullable_to_non_nullable
as String,index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as int,
  ));
}


}

/// @nodoc


class KeyRef_Imported extends KeyRef {
  const KeyRef_Imported({required this.seed, required this.network, required this.index}): super._();
  

 final  String seed;
 final  String network;
 final  int index;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KeyRef_ImportedCopyWith<KeyRef_Imported> get copyWith => _$KeyRef_ImportedCopyWithImpl<KeyRef_Imported>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KeyRef_Imported&&(identical(other.seed, seed) || other.seed == seed)&&(identical(other.network, network) || other.network == network)&&(identical(other.index, index) || other.index == index));
}


@override
int get hashCode => Object.hash(runtimeType,seed,network,index);

@override
String toString() {
  return 'KeyRef.imported(seed: $seed, network: $network, index: $index)';
}


}

/// @nodoc
abstract mixin class $KeyRef_ImportedCopyWith<$Res> implements $KeyRefCopyWith<$Res> {
  factory $KeyRef_ImportedCopyWith(KeyRef_Imported value, $Res Function(KeyRef_Imported) _then) = _$KeyRef_ImportedCopyWithImpl;
@useResult
$Res call({
 String seed, String network, int index
});




}
/// @nodoc
class _$KeyRef_ImportedCopyWithImpl<$Res>
    implements $KeyRef_ImportedCopyWith<$Res> {
  _$KeyRef_ImportedCopyWithImpl(this._self, this._then);

  final KeyRef_Imported _self;
  final $Res Function(KeyRef_Imported) _then;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? seed = null,Object? network = null,Object? index = null,}) {
  return _then(KeyRef_Imported(
seed: null == seed ? _self.seed : seed // ignore: cast_nullable_to_non_nullable
as String,network: null == network ? _self.network : network // ignore: cast_nullable_to_non_nullable
as String,index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as int,
  ));
}


}

/// @nodoc


class KeyRef_Key extends KeyRef {
  const KeyRef_Key({required this.seed, required this.id}): super._();
  

 final  String seed;
 final  String id;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KeyRef_KeyCopyWith<KeyRef_Key> get copyWith => _$KeyRef_KeyCopyWithImpl<KeyRef_Key>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KeyRef_Key&&(identical(other.seed, seed) || other.seed == seed)&&(identical(other.id, id) || other.id == id));
}


@override
int get hashCode => Object.hash(runtimeType,seed,id);

@override
String toString() {
  return 'KeyRef.key(seed: $seed, id: $id)';
}


}

/// @nodoc
abstract mixin class $KeyRef_KeyCopyWith<$Res> implements $KeyRefCopyWith<$Res> {
  factory $KeyRef_KeyCopyWith(KeyRef_Key value, $Res Function(KeyRef_Key) _then) = _$KeyRef_KeyCopyWithImpl;
@useResult
$Res call({
 String seed, String id
});




}
/// @nodoc
class _$KeyRef_KeyCopyWithImpl<$Res>
    implements $KeyRef_KeyCopyWith<$Res> {
  _$KeyRef_KeyCopyWithImpl(this._self, this._then);

  final KeyRef_Key _self;
  final $Res Function(KeyRef_Key) _then;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? seed = null,Object? id = null,}) {
  return _then(KeyRef_Key(
seed: null == seed ? _self.seed : seed // ignore: cast_nullable_to_non_nullable
as String,id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class KeyRef_Msig extends KeyRef {
  const KeyRef_Msig({required this.ua, required final  List<MsigSlot> slots}): _slots = slots,super._();
  

 final  String ua;
 final  List<MsigSlot> _slots;
 List<MsigSlot> get slots {
  if (_slots is EqualUnmodifiableListView) return _slots;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_slots);
}


/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KeyRef_MsigCopyWith<KeyRef_Msig> get copyWith => _$KeyRef_MsigCopyWithImpl<KeyRef_Msig>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KeyRef_Msig&&(identical(other.ua, ua) || other.ua == ua)&&const DeepCollectionEquality().equals(other._slots, _slots));
}


@override
int get hashCode => Object.hash(runtimeType,ua,const DeepCollectionEquality().hash(_slots));

@override
String toString() {
  return 'KeyRef.msig(ua: $ua, slots: $slots)';
}


}

/// @nodoc
abstract mixin class $KeyRef_MsigCopyWith<$Res> implements $KeyRefCopyWith<$Res> {
  factory $KeyRef_MsigCopyWith(KeyRef_Msig value, $Res Function(KeyRef_Msig) _then) = _$KeyRef_MsigCopyWithImpl;
@useResult
$Res call({
 String ua, List<MsigSlot> slots
});




}
/// @nodoc
class _$KeyRef_MsigCopyWithImpl<$Res>
    implements $KeyRef_MsigCopyWith<$Res> {
  _$KeyRef_MsigCopyWithImpl(this._self, this._then);

  final KeyRef_Msig _self;
  final $Res Function(KeyRef_Msig) _then;

/// Create a copy of KeyRef
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? ua = null,Object? slots = null,}) {
  return _then(KeyRef_Msig(
ua: null == ua ? _self.ua : ua // ignore: cast_nullable_to_non_nullable
as String,slots: null == slots ? _self._slots : slots // ignore: cast_nullable_to_non_nullable
as List<MsigSlot>,
  ));
}


}

/// @nodoc
mixin _$MsigSlot {

 int get index;
/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MsigSlotCopyWith<MsigSlot> get copyWith => _$MsigSlotCopyWithImpl<MsigSlot>(this as MsigSlot, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MsigSlot&&(identical(other.index, index) || other.index == index));
}


@override
int get hashCode => Object.hash(runtimeType,index);

@override
String toString() {
  return 'MsigSlot(index: $index)';
}


}

/// @nodoc
abstract mixin class $MsigSlotCopyWith<$Res>  {
  factory $MsigSlotCopyWith(MsigSlot value, $Res Function(MsigSlot) _then) = _$MsigSlotCopyWithImpl;
@useResult
$Res call({
 int index
});




}
/// @nodoc
class _$MsigSlotCopyWithImpl<$Res>
    implements $MsigSlotCopyWith<$Res> {
  _$MsigSlotCopyWithImpl(this._self, this._then);

  final MsigSlot _self;
  final $Res Function(MsigSlot) _then;

/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? index = null,}) {
  return _then(_self.copyWith(
index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as int,
  ));
}

}


/// Adds pattern-matching-related methods to [MsigSlot].
extension MsigSlotPatterns on MsigSlot {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( MsigSlot_Member value)?  member,TResult Function( MsigSlot_Msig value)?  msig,TResult Function( MsigSlot_Signed value)?  signed,required TResult orElse(),}){
final _that = this;
switch (_that) {
case MsigSlot_Member() when member != null:
return member(_that);case MsigSlot_Msig() when msig != null:
return msig(_that);case MsigSlot_Signed() when signed != null:
return signed(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( MsigSlot_Member value)  member,required TResult Function( MsigSlot_Msig value)  msig,required TResult Function( MsigSlot_Signed value)  signed,}){
final _that = this;
switch (_that) {
case MsigSlot_Member():
return member(_that);case MsigSlot_Msig():
return msig(_that);case MsigSlot_Signed():
return signed(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( MsigSlot_Member value)?  member,TResult? Function( MsigSlot_Msig value)?  msig,TResult? Function( MsigSlot_Signed value)?  signed,}){
final _that = this;
switch (_that) {
case MsigSlot_Member() when member != null:
return member(_that);case MsigSlot_Msig() when msig != null:
return msig(_that);case MsigSlot_Signed() when signed != null:
return signed(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( int index,  KeyRef key)?  member,TResult Function( int index,  List<MsigLeaf> members)?  msig,TResult Function( int index,  String member)?  signed,required TResult orElse(),}) {final _that = this;
switch (_that) {
case MsigSlot_Member() when member != null:
return member(_that.index,_that.key);case MsigSlot_Msig() when msig != null:
return msig(_that.index,_that.members);case MsigSlot_Signed() when signed != null:
return signed(_that.index,_that.member);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( int index,  KeyRef key)  member,required TResult Function( int index,  List<MsigLeaf> members)  msig,required TResult Function( int index,  String member)  signed,}) {final _that = this;
switch (_that) {
case MsigSlot_Member():
return member(_that.index,_that.key);case MsigSlot_Msig():
return msig(_that.index,_that.members);case MsigSlot_Signed():
return signed(_that.index,_that.member);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( int index,  KeyRef key)?  member,TResult? Function( int index,  List<MsigLeaf> members)?  msig,TResult? Function( int index,  String member)?  signed,}) {final _that = this;
switch (_that) {
case MsigSlot_Member() when member != null:
return member(_that.index,_that.key);case MsigSlot_Msig() when msig != null:
return msig(_that.index,_that.members);case MsigSlot_Signed() when signed != null:
return signed(_that.index,_that.member);case _:
  return null;

}
}

}

/// @nodoc


class MsigSlot_Member extends MsigSlot {
  const MsigSlot_Member({required this.index, required this.key}): super._();
  

@override final  int index;
 final  KeyRef key;

/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MsigSlot_MemberCopyWith<MsigSlot_Member> get copyWith => _$MsigSlot_MemberCopyWithImpl<MsigSlot_Member>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MsigSlot_Member&&(identical(other.index, index) || other.index == index)&&(identical(other.key, key) || other.key == key));
}


@override
int get hashCode => Object.hash(runtimeType,index,key);

@override
String toString() {
  return 'MsigSlot.member(index: $index, key: $key)';
}


}

/// @nodoc
abstract mixin class $MsigSlot_MemberCopyWith<$Res> implements $MsigSlotCopyWith<$Res> {
  factory $MsigSlot_MemberCopyWith(MsigSlot_Member value, $Res Function(MsigSlot_Member) _then) = _$MsigSlot_MemberCopyWithImpl;
@override @useResult
$Res call({
 int index, KeyRef key
});


$KeyRefCopyWith<$Res> get key;

}
/// @nodoc
class _$MsigSlot_MemberCopyWithImpl<$Res>
    implements $MsigSlot_MemberCopyWith<$Res> {
  _$MsigSlot_MemberCopyWithImpl(this._self, this._then);

  final MsigSlot_Member _self;
  final $Res Function(MsigSlot_Member) _then;

/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? index = null,Object? key = null,}) {
  return _then(MsigSlot_Member(
index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as int,key: null == key ? _self.key : key // ignore: cast_nullable_to_non_nullable
as KeyRef,
  ));
}

/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$KeyRefCopyWith<$Res> get key {
  
  return $KeyRefCopyWith<$Res>(_self.key, (value) {
    return _then(_self.copyWith(key: value));
  });
}
}

/// @nodoc


class MsigSlot_Msig extends MsigSlot {
  const MsigSlot_Msig({required this.index, required final  List<MsigLeaf> members}): _members = members,super._();
  

@override final  int index;
 final  List<MsigLeaf> _members;
 List<MsigLeaf> get members {
  if (_members is EqualUnmodifiableListView) return _members;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_members);
}


/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MsigSlot_MsigCopyWith<MsigSlot_Msig> get copyWith => _$MsigSlot_MsigCopyWithImpl<MsigSlot_Msig>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MsigSlot_Msig&&(identical(other.index, index) || other.index == index)&&const DeepCollectionEquality().equals(other._members, _members));
}


@override
int get hashCode => Object.hash(runtimeType,index,const DeepCollectionEquality().hash(_members));

@override
String toString() {
  return 'MsigSlot.msig(index: $index, members: $members)';
}


}

/// @nodoc
abstract mixin class $MsigSlot_MsigCopyWith<$Res> implements $MsigSlotCopyWith<$Res> {
  factory $MsigSlot_MsigCopyWith(MsigSlot_Msig value, $Res Function(MsigSlot_Msig) _then) = _$MsigSlot_MsigCopyWithImpl;
@override @useResult
$Res call({
 int index, List<MsigLeaf> members
});




}
/// @nodoc
class _$MsigSlot_MsigCopyWithImpl<$Res>
    implements $MsigSlot_MsigCopyWith<$Res> {
  _$MsigSlot_MsigCopyWithImpl(this._self, this._then);

  final MsigSlot_Msig _self;
  final $Res Function(MsigSlot_Msig) _then;

/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? index = null,Object? members = null,}) {
  return _then(MsigSlot_Msig(
index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as int,members: null == members ? _self._members : members // ignore: cast_nullable_to_non_nullable
as List<MsigLeaf>,
  ));
}


}

/// @nodoc


class MsigSlot_Signed extends MsigSlot {
  const MsigSlot_Signed({required this.index, required this.member}): super._();
  

@override final  int index;
 final  String member;

/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MsigSlot_SignedCopyWith<MsigSlot_Signed> get copyWith => _$MsigSlot_SignedCopyWithImpl<MsigSlot_Signed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MsigSlot_Signed&&(identical(other.index, index) || other.index == index)&&(identical(other.member, member) || other.member == member));
}


@override
int get hashCode => Object.hash(runtimeType,index,member);

@override
String toString() {
  return 'MsigSlot.signed(index: $index, member: $member)';
}


}

/// @nodoc
abstract mixin class $MsigSlot_SignedCopyWith<$Res> implements $MsigSlotCopyWith<$Res> {
  factory $MsigSlot_SignedCopyWith(MsigSlot_Signed value, $Res Function(MsigSlot_Signed) _then) = _$MsigSlot_SignedCopyWithImpl;
@override @useResult
$Res call({
 int index, String member
});




}
/// @nodoc
class _$MsigSlot_SignedCopyWithImpl<$Res>
    implements $MsigSlot_SignedCopyWith<$Res> {
  _$MsigSlot_SignedCopyWithImpl(this._self, this._then);

  final MsigSlot_Signed _self;
  final $Res Function(MsigSlot_Signed) _then;

/// Create a copy of MsigSlot
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? index = null,Object? member = null,}) {
  return _then(MsigSlot_Signed(
index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as int,member: null == member ? _self.member : member // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc
mixin _$SubmitPath {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is SubmitPath);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'SubmitPath()';
}


}

/// @nodoc
class $SubmitPathCopyWith<$Res>  {
$SubmitPathCopyWith(SubmitPath _, $Res Function(SubmitPath) __);
}


/// Adds pattern-matching-related methods to [SubmitPath].
extension SubmitPathPatterns on SubmitPath {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( SubmitPath_Auto value)?  auto,TResult Function( SubmitPath_Gateway value)?  gateway,TResult Function( SubmitPath_SelfRelay value)?  selfRelay,required TResult orElse(),}){
final _that = this;
switch (_that) {
case SubmitPath_Auto() when auto != null:
return auto(_that);case SubmitPath_Gateway() when gateway != null:
return gateway(_that);case SubmitPath_SelfRelay() when selfRelay != null:
return selfRelay(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( SubmitPath_Auto value)  auto,required TResult Function( SubmitPath_Gateway value)  gateway,required TResult Function( SubmitPath_SelfRelay value)  selfRelay,}){
final _that = this;
switch (_that) {
case SubmitPath_Auto():
return auto(_that);case SubmitPath_Gateway():
return gateway(_that);case SubmitPath_SelfRelay():
return selfRelay(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( SubmitPath_Auto value)?  auto,TResult? Function( SubmitPath_Gateway value)?  gateway,TResult? Function( SubmitPath_SelfRelay value)?  selfRelay,}){
final _that = this;
switch (_that) {
case SubmitPath_Auto() when auto != null:
return auto(_that);case SubmitPath_Gateway() when gateway != null:
return gateway(_that);case SubmitPath_SelfRelay() when selfRelay != null:
return selfRelay(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( KeyRef? payer)?  auto,TResult Function()?  gateway,TResult Function( KeyRef payer)?  selfRelay,required TResult orElse(),}) {final _that = this;
switch (_that) {
case SubmitPath_Auto() when auto != null:
return auto(_that.payer);case SubmitPath_Gateway() when gateway != null:
return gateway();case SubmitPath_SelfRelay() when selfRelay != null:
return selfRelay(_that.payer);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( KeyRef? payer)  auto,required TResult Function()  gateway,required TResult Function( KeyRef payer)  selfRelay,}) {final _that = this;
switch (_that) {
case SubmitPath_Auto():
return auto(_that.payer);case SubmitPath_Gateway():
return gateway();case SubmitPath_SelfRelay():
return selfRelay(_that.payer);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( KeyRef? payer)?  auto,TResult? Function()?  gateway,TResult? Function( KeyRef payer)?  selfRelay,}) {final _that = this;
switch (_that) {
case SubmitPath_Auto() when auto != null:
return auto(_that.payer);case SubmitPath_Gateway() when gateway != null:
return gateway();case SubmitPath_SelfRelay() when selfRelay != null:
return selfRelay(_that.payer);case _:
  return null;

}
}

}

/// @nodoc


class SubmitPath_Auto extends SubmitPath {
  const SubmitPath_Auto({this.payer}): super._();
  

 final  KeyRef? payer;

/// Create a copy of SubmitPath
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SubmitPath_AutoCopyWith<SubmitPath_Auto> get copyWith => _$SubmitPath_AutoCopyWithImpl<SubmitPath_Auto>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is SubmitPath_Auto&&(identical(other.payer, payer) || other.payer == payer));
}


@override
int get hashCode => Object.hash(runtimeType,payer);

@override
String toString() {
  return 'SubmitPath.auto(payer: $payer)';
}


}

/// @nodoc
abstract mixin class $SubmitPath_AutoCopyWith<$Res> implements $SubmitPathCopyWith<$Res> {
  factory $SubmitPath_AutoCopyWith(SubmitPath_Auto value, $Res Function(SubmitPath_Auto) _then) = _$SubmitPath_AutoCopyWithImpl;
@useResult
$Res call({
 KeyRef? payer
});


$KeyRefCopyWith<$Res>? get payer;

}
/// @nodoc
class _$SubmitPath_AutoCopyWithImpl<$Res>
    implements $SubmitPath_AutoCopyWith<$Res> {
  _$SubmitPath_AutoCopyWithImpl(this._self, this._then);

  final SubmitPath_Auto _self;
  final $Res Function(SubmitPath_Auto) _then;

/// Create a copy of SubmitPath
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? payer = freezed,}) {
  return _then(SubmitPath_Auto(
payer: freezed == payer ? _self.payer : payer // ignore: cast_nullable_to_non_nullable
as KeyRef?,
  ));
}

/// Create a copy of SubmitPath
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$KeyRefCopyWith<$Res>? get payer {
    if (_self.payer == null) {
    return null;
  }

  return $KeyRefCopyWith<$Res>(_self.payer!, (value) {
    return _then(_self.copyWith(payer: value));
  });
}
}

/// @nodoc


class SubmitPath_Gateway extends SubmitPath {
  const SubmitPath_Gateway(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is SubmitPath_Gateway);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'SubmitPath.gateway()';
}


}




/// @nodoc


class SubmitPath_SelfRelay extends SubmitPath {
  const SubmitPath_SelfRelay({required this.payer}): super._();
  

 final  KeyRef payer;

/// Create a copy of SubmitPath
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SubmitPath_SelfRelayCopyWith<SubmitPath_SelfRelay> get copyWith => _$SubmitPath_SelfRelayCopyWithImpl<SubmitPath_SelfRelay>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is SubmitPath_SelfRelay&&(identical(other.payer, payer) || other.payer == payer));
}


@override
int get hashCode => Object.hash(runtimeType,payer);

@override
String toString() {
  return 'SubmitPath.selfRelay(payer: $payer)';
}


}

/// @nodoc
abstract mixin class $SubmitPath_SelfRelayCopyWith<$Res> implements $SubmitPathCopyWith<$Res> {
  factory $SubmitPath_SelfRelayCopyWith(SubmitPath_SelfRelay value, $Res Function(SubmitPath_SelfRelay) _then) = _$SubmitPath_SelfRelayCopyWithImpl;
@useResult
$Res call({
 KeyRef payer
});


$KeyRefCopyWith<$Res> get payer;

}
/// @nodoc
class _$SubmitPath_SelfRelayCopyWithImpl<$Res>
    implements $SubmitPath_SelfRelayCopyWith<$Res> {
  _$SubmitPath_SelfRelayCopyWithImpl(this._self, this._then);

  final SubmitPath_SelfRelay _self;
  final $Res Function(SubmitPath_SelfRelay) _then;

/// Create a copy of SubmitPath
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? payer = null,}) {
  return _then(SubmitPath_SelfRelay(
payer: null == payer ? _self.payer : payer // ignore: cast_nullable_to_non_nullable
as KeyRef,
  ));
}

/// Create a copy of SubmitPath
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$KeyRefCopyWith<$Res> get payer {
  
  return $KeyRefCopyWith<$Res>(_self.payer, (value) {
    return _then(_self.copyWith(payer: value));
  });
}
}

// dart format on
