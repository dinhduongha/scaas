// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'keystore.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$AccountRow {

 String get id; String get name;
/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AccountRowCopyWith<AccountRow> get copyWith => _$AccountRowCopyWithImpl<AccountRow>(this as AccountRow, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AccountRow&&(identical(other.id, id) || other.id == id)&&(identical(other.name, name) || other.name == name));
}


@override
int get hashCode => Object.hash(runtimeType,id,name);

@override
String toString() {
  return 'AccountRow(id: $id, name: $name)';
}


}

/// @nodoc
abstract mixin class $AccountRowCopyWith<$Res>  {
  factory $AccountRowCopyWith(AccountRow value, $Res Function(AccountRow) _then) = _$AccountRowCopyWithImpl;
@useResult
$Res call({
 String id, String name
});




}
/// @nodoc
class _$AccountRowCopyWithImpl<$Res>
    implements $AccountRowCopyWith<$Res> {
  _$AccountRowCopyWithImpl(this._self, this._then);

  final AccountRow _self;
  final $Res Function(AccountRow) _then;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? id = null,Object? name = null,}) {
  return _then(_self.copyWith(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as String,name: null == name ? _self.name : name // ignore: cast_nullable_to_non_nullable
as String,
  ));
}

}


/// Adds pattern-matching-related methods to [AccountRow].
extension AccountRowPatterns on AccountRow {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( AccountRow_Ua value)?  ua,TResult Function( AccountRow_Native value)?  native,TResult Function( AccountRow_Key value)?  key,TResult Function( AccountRow_Watch value)?  watch,required TResult orElse(),}){
final _that = this;
switch (_that) {
case AccountRow_Ua() when ua != null:
return ua(_that);case AccountRow_Native() when native != null:
return native(_that);case AccountRow_Key() when key != null:
return key(_that);case AccountRow_Watch() when watch != null:
return watch(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( AccountRow_Ua value)  ua,required TResult Function( AccountRow_Native value)  native,required TResult Function( AccountRow_Key value)  key,required TResult Function( AccountRow_Watch value)  watch,}){
final _that = this;
switch (_that) {
case AccountRow_Ua():
return ua(_that);case AccountRow_Native():
return native(_that);case AccountRow_Key():
return key(_that);case AccountRow_Watch():
return watch(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( AccountRow_Ua value)?  ua,TResult? Function( AccountRow_Native value)?  native,TResult? Function( AccountRow_Key value)?  key,TResult? Function( AccountRow_Watch value)?  watch,}){
final _that = this;
switch (_that) {
case AccountRow_Ua() when ua != null:
return ua(_that);case AccountRow_Native() when native != null:
return native(_that);case AccountRow_Key() when key != null:
return key(_that);case AccountRow_Watch() when watch != null:
return watch(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String id,  String name,  BigInt kind,  BigInt account,  BigInt index,  String ua)?  ua,TResult Function( String id,  String name,  String network,  BigInt index,  BigInt? coinType,  BigInt? change,  String? path,  BigInt? ss58Prefix,  String address)?  native,TResult Function( String id,  String name,  BigInt kind,  String keyData,  String? credentialId,  String? handle,  String ua)?  key,TResult Function( String id,  String name,  String watch)?  watch,required TResult orElse(),}) {final _that = this;
switch (_that) {
case AccountRow_Ua() when ua != null:
return ua(_that.id,_that.name,_that.kind,_that.account,_that.index,_that.ua);case AccountRow_Native() when native != null:
return native(_that.id,_that.name,_that.network,_that.index,_that.coinType,_that.change,_that.path,_that.ss58Prefix,_that.address);case AccountRow_Key() when key != null:
return key(_that.id,_that.name,_that.kind,_that.keyData,_that.credentialId,_that.handle,_that.ua);case AccountRow_Watch() when watch != null:
return watch(_that.id,_that.name,_that.watch);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String id,  String name,  BigInt kind,  BigInt account,  BigInt index,  String ua)  ua,required TResult Function( String id,  String name,  String network,  BigInt index,  BigInt? coinType,  BigInt? change,  String? path,  BigInt? ss58Prefix,  String address)  native,required TResult Function( String id,  String name,  BigInt kind,  String keyData,  String? credentialId,  String? handle,  String ua)  key,required TResult Function( String id,  String name,  String watch)  watch,}) {final _that = this;
switch (_that) {
case AccountRow_Ua():
return ua(_that.id,_that.name,_that.kind,_that.account,_that.index,_that.ua);case AccountRow_Native():
return native(_that.id,_that.name,_that.network,_that.index,_that.coinType,_that.change,_that.path,_that.ss58Prefix,_that.address);case AccountRow_Key():
return key(_that.id,_that.name,_that.kind,_that.keyData,_that.credentialId,_that.handle,_that.ua);case AccountRow_Watch():
return watch(_that.id,_that.name,_that.watch);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String id,  String name,  BigInt kind,  BigInt account,  BigInt index,  String ua)?  ua,TResult? Function( String id,  String name,  String network,  BigInt index,  BigInt? coinType,  BigInt? change,  String? path,  BigInt? ss58Prefix,  String address)?  native,TResult? Function( String id,  String name,  BigInt kind,  String keyData,  String? credentialId,  String? handle,  String ua)?  key,TResult? Function( String id,  String name,  String watch)?  watch,}) {final _that = this;
switch (_that) {
case AccountRow_Ua() when ua != null:
return ua(_that.id,_that.name,_that.kind,_that.account,_that.index,_that.ua);case AccountRow_Native() when native != null:
return native(_that.id,_that.name,_that.network,_that.index,_that.coinType,_that.change,_that.path,_that.ss58Prefix,_that.address);case AccountRow_Key() when key != null:
return key(_that.id,_that.name,_that.kind,_that.keyData,_that.credentialId,_that.handle,_that.ua);case AccountRow_Watch() when watch != null:
return watch(_that.id,_that.name,_that.watch);case _:
  return null;

}
}

}

/// @nodoc


class AccountRow_Ua extends AccountRow {
  const AccountRow_Ua({required this.id, required this.name, required this.kind, required this.account, required this.index, required this.ua}): super._();
  

@override final  String id;
@override final  String name;
 final  BigInt kind;
 final  BigInt account;
 final  BigInt index;
 final  String ua;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AccountRow_UaCopyWith<AccountRow_Ua> get copyWith => _$AccountRow_UaCopyWithImpl<AccountRow_Ua>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AccountRow_Ua&&(identical(other.id, id) || other.id == id)&&(identical(other.name, name) || other.name == name)&&(identical(other.kind, kind) || other.kind == kind)&&(identical(other.account, account) || other.account == account)&&(identical(other.index, index) || other.index == index)&&(identical(other.ua, ua) || other.ua == ua));
}


@override
int get hashCode => Object.hash(runtimeType,id,name,kind,account,index,ua);

@override
String toString() {
  return 'AccountRow.ua(id: $id, name: $name, kind: $kind, account: $account, index: $index, ua: $ua)';
}


}

/// @nodoc
abstract mixin class $AccountRow_UaCopyWith<$Res> implements $AccountRowCopyWith<$Res> {
  factory $AccountRow_UaCopyWith(AccountRow_Ua value, $Res Function(AccountRow_Ua) _then) = _$AccountRow_UaCopyWithImpl;
@override @useResult
$Res call({
 String id, String name, BigInt kind, BigInt account, BigInt index, String ua
});




}
/// @nodoc
class _$AccountRow_UaCopyWithImpl<$Res>
    implements $AccountRow_UaCopyWith<$Res> {
  _$AccountRow_UaCopyWithImpl(this._self, this._then);

  final AccountRow_Ua _self;
  final $Res Function(AccountRow_Ua) _then;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? id = null,Object? name = null,Object? kind = null,Object? account = null,Object? index = null,Object? ua = null,}) {
  return _then(AccountRow_Ua(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as String,name: null == name ? _self.name : name // ignore: cast_nullable_to_non_nullable
as String,kind: null == kind ? _self.kind : kind // ignore: cast_nullable_to_non_nullable
as BigInt,account: null == account ? _self.account : account // ignore: cast_nullable_to_non_nullable
as BigInt,index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as BigInt,ua: null == ua ? _self.ua : ua // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AccountRow_Native extends AccountRow {
  const AccountRow_Native({required this.id, required this.name, required this.network, required this.index, this.coinType, this.change, this.path, this.ss58Prefix, required this.address}): super._();
  

@override final  String id;
@override final  String name;
 final  String network;
 final  BigInt index;
 final  BigInt? coinType;
 final  BigInt? change;
 final  String? path;
 final  BigInt? ss58Prefix;
 final  String address;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AccountRow_NativeCopyWith<AccountRow_Native> get copyWith => _$AccountRow_NativeCopyWithImpl<AccountRow_Native>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AccountRow_Native&&(identical(other.id, id) || other.id == id)&&(identical(other.name, name) || other.name == name)&&(identical(other.network, network) || other.network == network)&&(identical(other.index, index) || other.index == index)&&(identical(other.coinType, coinType) || other.coinType == coinType)&&(identical(other.change, change) || other.change == change)&&(identical(other.path, path) || other.path == path)&&(identical(other.ss58Prefix, ss58Prefix) || other.ss58Prefix == ss58Prefix)&&(identical(other.address, address) || other.address == address));
}


@override
int get hashCode => Object.hash(runtimeType,id,name,network,index,coinType,change,path,ss58Prefix,address);

@override
String toString() {
  return 'AccountRow.native(id: $id, name: $name, network: $network, index: $index, coinType: $coinType, change: $change, path: $path, ss58Prefix: $ss58Prefix, address: $address)';
}


}

/// @nodoc
abstract mixin class $AccountRow_NativeCopyWith<$Res> implements $AccountRowCopyWith<$Res> {
  factory $AccountRow_NativeCopyWith(AccountRow_Native value, $Res Function(AccountRow_Native) _then) = _$AccountRow_NativeCopyWithImpl;
@override @useResult
$Res call({
 String id, String name, String network, BigInt index, BigInt? coinType, BigInt? change, String? path, BigInt? ss58Prefix, String address
});




}
/// @nodoc
class _$AccountRow_NativeCopyWithImpl<$Res>
    implements $AccountRow_NativeCopyWith<$Res> {
  _$AccountRow_NativeCopyWithImpl(this._self, this._then);

  final AccountRow_Native _self;
  final $Res Function(AccountRow_Native) _then;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? id = null,Object? name = null,Object? network = null,Object? index = null,Object? coinType = freezed,Object? change = freezed,Object? path = freezed,Object? ss58Prefix = freezed,Object? address = null,}) {
  return _then(AccountRow_Native(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as String,name: null == name ? _self.name : name // ignore: cast_nullable_to_non_nullable
as String,network: null == network ? _self.network : network // ignore: cast_nullable_to_non_nullable
as String,index: null == index ? _self.index : index // ignore: cast_nullable_to_non_nullable
as BigInt,coinType: freezed == coinType ? _self.coinType : coinType // ignore: cast_nullable_to_non_nullable
as BigInt?,change: freezed == change ? _self.change : change // ignore: cast_nullable_to_non_nullable
as BigInt?,path: freezed == path ? _self.path : path // ignore: cast_nullable_to_non_nullable
as String?,ss58Prefix: freezed == ss58Prefix ? _self.ss58Prefix : ss58Prefix // ignore: cast_nullable_to_non_nullable
as BigInt?,address: null == address ? _self.address : address // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AccountRow_Key extends AccountRow {
  const AccountRow_Key({required this.id, required this.name, required this.kind, required this.keyData, this.credentialId, this.handle, required this.ua}): super._();
  

@override final  String id;
@override final  String name;
 final  BigInt kind;
 final  String keyData;
 final  String? credentialId;
 final  String? handle;
 final  String ua;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AccountRow_KeyCopyWith<AccountRow_Key> get copyWith => _$AccountRow_KeyCopyWithImpl<AccountRow_Key>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AccountRow_Key&&(identical(other.id, id) || other.id == id)&&(identical(other.name, name) || other.name == name)&&(identical(other.kind, kind) || other.kind == kind)&&(identical(other.keyData, keyData) || other.keyData == keyData)&&(identical(other.credentialId, credentialId) || other.credentialId == credentialId)&&(identical(other.handle, handle) || other.handle == handle)&&(identical(other.ua, ua) || other.ua == ua));
}


@override
int get hashCode => Object.hash(runtimeType,id,name,kind,keyData,credentialId,handle,ua);

@override
String toString() {
  return 'AccountRow.key(id: $id, name: $name, kind: $kind, keyData: $keyData, credentialId: $credentialId, handle: $handle, ua: $ua)';
}


}

/// @nodoc
abstract mixin class $AccountRow_KeyCopyWith<$Res> implements $AccountRowCopyWith<$Res> {
  factory $AccountRow_KeyCopyWith(AccountRow_Key value, $Res Function(AccountRow_Key) _then) = _$AccountRow_KeyCopyWithImpl;
@override @useResult
$Res call({
 String id, String name, BigInt kind, String keyData, String? credentialId, String? handle, String ua
});




}
/// @nodoc
class _$AccountRow_KeyCopyWithImpl<$Res>
    implements $AccountRow_KeyCopyWith<$Res> {
  _$AccountRow_KeyCopyWithImpl(this._self, this._then);

  final AccountRow_Key _self;
  final $Res Function(AccountRow_Key) _then;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? id = null,Object? name = null,Object? kind = null,Object? keyData = null,Object? credentialId = freezed,Object? handle = freezed,Object? ua = null,}) {
  return _then(AccountRow_Key(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as String,name: null == name ? _self.name : name // ignore: cast_nullable_to_non_nullable
as String,kind: null == kind ? _self.kind : kind // ignore: cast_nullable_to_non_nullable
as BigInt,keyData: null == keyData ? _self.keyData : keyData // ignore: cast_nullable_to_non_nullable
as String,credentialId: freezed == credentialId ? _self.credentialId : credentialId // ignore: cast_nullable_to_non_nullable
as String?,handle: freezed == handle ? _self.handle : handle // ignore: cast_nullable_to_non_nullable
as String?,ua: null == ua ? _self.ua : ua // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AccountRow_Watch extends AccountRow {
  const AccountRow_Watch({required this.id, required this.name, required this.watch}): super._();
  

@override final  String id;
@override final  String name;
 final  String watch;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AccountRow_WatchCopyWith<AccountRow_Watch> get copyWith => _$AccountRow_WatchCopyWithImpl<AccountRow_Watch>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AccountRow_Watch&&(identical(other.id, id) || other.id == id)&&(identical(other.name, name) || other.name == name)&&(identical(other.watch, watch) || other.watch == watch));
}


@override
int get hashCode => Object.hash(runtimeType,id,name,watch);

@override
String toString() {
  return 'AccountRow.watch(id: $id, name: $name, watch: $watch)';
}


}

/// @nodoc
abstract mixin class $AccountRow_WatchCopyWith<$Res> implements $AccountRowCopyWith<$Res> {
  factory $AccountRow_WatchCopyWith(AccountRow_Watch value, $Res Function(AccountRow_Watch) _then) = _$AccountRow_WatchCopyWithImpl;
@override @useResult
$Res call({
 String id, String name, String watch
});




}
/// @nodoc
class _$AccountRow_WatchCopyWithImpl<$Res>
    implements $AccountRow_WatchCopyWith<$Res> {
  _$AccountRow_WatchCopyWithImpl(this._self, this._then);

  final AccountRow_Watch _self;
  final $Res Function(AccountRow_Watch) _then;

/// Create a copy of AccountRow
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? id = null,Object? name = null,Object? watch = null,}) {
  return _then(AccountRow_Watch(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as String,name: null == name ? _self.name : name // ignore: cast_nullable_to_non_nullable
as String,watch: null == watch ? _self.watch : watch // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
