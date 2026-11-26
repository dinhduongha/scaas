// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'events.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$Event {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'Event()';
}


}

/// @nodoc
class $EventCopyWith<$Res>  {
$EventCopyWith(Event _, $Res Function(Event) __);
}


/// Adds pattern-matching-related methods to [Event].
extension EventPatterns on Event {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( Event_SeedUnlocked value)?  seedUnlocked,TResult Function( Event_SeedLocked value)?  seedLocked,TResult Function( Event_KeystoreChanged value)?  keystoreChanged,TResult Function( Event_KeystoreMismatch value)?  keystoreMismatch,TResult Function( Event_KeystoreRollback value)?  keystoreRollback,TResult Function( Event_HiddenOpsAbandoned value)?  hiddenOpsAbandoned,TResult Function( Event_Lagged value)?  lagged,TResult Function( Event_OpState value)?  opState,TResult Function( Event_BalanceChanged value)?  balanceChanged,TResult Function( Event_HistoryAdded value)?  historyAdded,TResult Function( Event_StateChanged value)?  stateChanged,required TResult orElse(),}){
final _that = this;
switch (_that) {
case Event_SeedUnlocked() when seedUnlocked != null:
return seedUnlocked(_that);case Event_SeedLocked() when seedLocked != null:
return seedLocked(_that);case Event_KeystoreChanged() when keystoreChanged != null:
return keystoreChanged(_that);case Event_KeystoreMismatch() when keystoreMismatch != null:
return keystoreMismatch(_that);case Event_KeystoreRollback() when keystoreRollback != null:
return keystoreRollback(_that);case Event_HiddenOpsAbandoned() when hiddenOpsAbandoned != null:
return hiddenOpsAbandoned(_that);case Event_Lagged() when lagged != null:
return lagged(_that);case Event_OpState() when opState != null:
return opState(_that);case Event_BalanceChanged() when balanceChanged != null:
return balanceChanged(_that);case Event_HistoryAdded() when historyAdded != null:
return historyAdded(_that);case Event_StateChanged() when stateChanged != null:
return stateChanged(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( Event_SeedUnlocked value)  seedUnlocked,required TResult Function( Event_SeedLocked value)  seedLocked,required TResult Function( Event_KeystoreChanged value)  keystoreChanged,required TResult Function( Event_KeystoreMismatch value)  keystoreMismatch,required TResult Function( Event_KeystoreRollback value)  keystoreRollback,required TResult Function( Event_HiddenOpsAbandoned value)  hiddenOpsAbandoned,required TResult Function( Event_Lagged value)  lagged,required TResult Function( Event_OpState value)  opState,required TResult Function( Event_BalanceChanged value)  balanceChanged,required TResult Function( Event_HistoryAdded value)  historyAdded,required TResult Function( Event_StateChanged value)  stateChanged,}){
final _that = this;
switch (_that) {
case Event_SeedUnlocked():
return seedUnlocked(_that);case Event_SeedLocked():
return seedLocked(_that);case Event_KeystoreChanged():
return keystoreChanged(_that);case Event_KeystoreMismatch():
return keystoreMismatch(_that);case Event_KeystoreRollback():
return keystoreRollback(_that);case Event_HiddenOpsAbandoned():
return hiddenOpsAbandoned(_that);case Event_Lagged():
return lagged(_that);case Event_OpState():
return opState(_that);case Event_BalanceChanged():
return balanceChanged(_that);case Event_HistoryAdded():
return historyAdded(_that);case Event_StateChanged():
return stateChanged(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( Event_SeedUnlocked value)?  seedUnlocked,TResult? Function( Event_SeedLocked value)?  seedLocked,TResult? Function( Event_KeystoreChanged value)?  keystoreChanged,TResult? Function( Event_KeystoreMismatch value)?  keystoreMismatch,TResult? Function( Event_KeystoreRollback value)?  keystoreRollback,TResult? Function( Event_HiddenOpsAbandoned value)?  hiddenOpsAbandoned,TResult? Function( Event_Lagged value)?  lagged,TResult? Function( Event_OpState value)?  opState,TResult? Function( Event_BalanceChanged value)?  balanceChanged,TResult? Function( Event_HistoryAdded value)?  historyAdded,TResult? Function( Event_StateChanged value)?  stateChanged,}){
final _that = this;
switch (_that) {
case Event_SeedUnlocked() when seedUnlocked != null:
return seedUnlocked(_that);case Event_SeedLocked() when seedLocked != null:
return seedLocked(_that);case Event_KeystoreChanged() when keystoreChanged != null:
return keystoreChanged(_that);case Event_KeystoreMismatch() when keystoreMismatch != null:
return keystoreMismatch(_that);case Event_KeystoreRollback() when keystoreRollback != null:
return keystoreRollback(_that);case Event_HiddenOpsAbandoned() when hiddenOpsAbandoned != null:
return hiddenOpsAbandoned(_that);case Event_Lagged() when lagged != null:
return lagged(_that);case Event_OpState() when opState != null:
return opState(_that);case Event_BalanceChanged() when balanceChanged != null:
return balanceChanged(_that);case Event_HistoryAdded() when historyAdded != null:
return historyAdded(_that);case Event_StateChanged() when stateChanged != null:
return stateChanged(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String seed)?  seedUnlocked,TResult Function( String seed)?  seedLocked,TResult Function( BigInt rev)?  keystoreChanged,TResult Function( String seed)?  keystoreMismatch,TResult Function()?  keystoreRollback,TResult Function( int count)?  hiddenOpsAbandoned,TResult Function( BigInt missed)?  lagged,TResult Function( String op,  OpState state)?  opState,TResult Function( String account,  String chain,  String token)?  balanceChanged,TResult Function( String account,  String chain,  List<HistoryItem> items)?  historyAdded,TResult Function( BigInt rev)?  stateChanged,required TResult orElse(),}) {final _that = this;
switch (_that) {
case Event_SeedUnlocked() when seedUnlocked != null:
return seedUnlocked(_that.seed);case Event_SeedLocked() when seedLocked != null:
return seedLocked(_that.seed);case Event_KeystoreChanged() when keystoreChanged != null:
return keystoreChanged(_that.rev);case Event_KeystoreMismatch() when keystoreMismatch != null:
return keystoreMismatch(_that.seed);case Event_KeystoreRollback() when keystoreRollback != null:
return keystoreRollback();case Event_HiddenOpsAbandoned() when hiddenOpsAbandoned != null:
return hiddenOpsAbandoned(_that.count);case Event_Lagged() when lagged != null:
return lagged(_that.missed);case Event_OpState() when opState != null:
return opState(_that.op,_that.state);case Event_BalanceChanged() when balanceChanged != null:
return balanceChanged(_that.account,_that.chain,_that.token);case Event_HistoryAdded() when historyAdded != null:
return historyAdded(_that.account,_that.chain,_that.items);case Event_StateChanged() when stateChanged != null:
return stateChanged(_that.rev);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String seed)  seedUnlocked,required TResult Function( String seed)  seedLocked,required TResult Function( BigInt rev)  keystoreChanged,required TResult Function( String seed)  keystoreMismatch,required TResult Function()  keystoreRollback,required TResult Function( int count)  hiddenOpsAbandoned,required TResult Function( BigInt missed)  lagged,required TResult Function( String op,  OpState state)  opState,required TResult Function( String account,  String chain,  String token)  balanceChanged,required TResult Function( String account,  String chain,  List<HistoryItem> items)  historyAdded,required TResult Function( BigInt rev)  stateChanged,}) {final _that = this;
switch (_that) {
case Event_SeedUnlocked():
return seedUnlocked(_that.seed);case Event_SeedLocked():
return seedLocked(_that.seed);case Event_KeystoreChanged():
return keystoreChanged(_that.rev);case Event_KeystoreMismatch():
return keystoreMismatch(_that.seed);case Event_KeystoreRollback():
return keystoreRollback();case Event_HiddenOpsAbandoned():
return hiddenOpsAbandoned(_that.count);case Event_Lagged():
return lagged(_that.missed);case Event_OpState():
return opState(_that.op,_that.state);case Event_BalanceChanged():
return balanceChanged(_that.account,_that.chain,_that.token);case Event_HistoryAdded():
return historyAdded(_that.account,_that.chain,_that.items);case Event_StateChanged():
return stateChanged(_that.rev);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String seed)?  seedUnlocked,TResult? Function( String seed)?  seedLocked,TResult? Function( BigInt rev)?  keystoreChanged,TResult? Function( String seed)?  keystoreMismatch,TResult? Function()?  keystoreRollback,TResult? Function( int count)?  hiddenOpsAbandoned,TResult? Function( BigInt missed)?  lagged,TResult? Function( String op,  OpState state)?  opState,TResult? Function( String account,  String chain,  String token)?  balanceChanged,TResult? Function( String account,  String chain,  List<HistoryItem> items)?  historyAdded,TResult? Function( BigInt rev)?  stateChanged,}) {final _that = this;
switch (_that) {
case Event_SeedUnlocked() when seedUnlocked != null:
return seedUnlocked(_that.seed);case Event_SeedLocked() when seedLocked != null:
return seedLocked(_that.seed);case Event_KeystoreChanged() when keystoreChanged != null:
return keystoreChanged(_that.rev);case Event_KeystoreMismatch() when keystoreMismatch != null:
return keystoreMismatch(_that.seed);case Event_KeystoreRollback() when keystoreRollback != null:
return keystoreRollback();case Event_HiddenOpsAbandoned() when hiddenOpsAbandoned != null:
return hiddenOpsAbandoned(_that.count);case Event_Lagged() when lagged != null:
return lagged(_that.missed);case Event_OpState() when opState != null:
return opState(_that.op,_that.state);case Event_BalanceChanged() when balanceChanged != null:
return balanceChanged(_that.account,_that.chain,_that.token);case Event_HistoryAdded() when historyAdded != null:
return historyAdded(_that.account,_that.chain,_that.items);case Event_StateChanged() when stateChanged != null:
return stateChanged(_that.rev);case _:
  return null;

}
}

}

/// @nodoc


class Event_SeedUnlocked extends Event {
  const Event_SeedUnlocked({required this.seed}): super._();
  

 final  String seed;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_SeedUnlockedCopyWith<Event_SeedUnlocked> get copyWith => _$Event_SeedUnlockedCopyWithImpl<Event_SeedUnlocked>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_SeedUnlocked&&(identical(other.seed, seed) || other.seed == seed));
}


@override
int get hashCode => Object.hash(runtimeType,seed);

@override
String toString() {
  return 'Event.seedUnlocked(seed: $seed)';
}


}

/// @nodoc
abstract mixin class $Event_SeedUnlockedCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_SeedUnlockedCopyWith(Event_SeedUnlocked value, $Res Function(Event_SeedUnlocked) _then) = _$Event_SeedUnlockedCopyWithImpl;
@useResult
$Res call({
 String seed
});




}
/// @nodoc
class _$Event_SeedUnlockedCopyWithImpl<$Res>
    implements $Event_SeedUnlockedCopyWith<$Res> {
  _$Event_SeedUnlockedCopyWithImpl(this._self, this._then);

  final Event_SeedUnlocked _self;
  final $Res Function(Event_SeedUnlocked) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? seed = null,}) {
  return _then(Event_SeedUnlocked(
seed: null == seed ? _self.seed : seed // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class Event_SeedLocked extends Event {
  const Event_SeedLocked({required this.seed}): super._();
  

 final  String seed;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_SeedLockedCopyWith<Event_SeedLocked> get copyWith => _$Event_SeedLockedCopyWithImpl<Event_SeedLocked>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_SeedLocked&&(identical(other.seed, seed) || other.seed == seed));
}


@override
int get hashCode => Object.hash(runtimeType,seed);

@override
String toString() {
  return 'Event.seedLocked(seed: $seed)';
}


}

/// @nodoc
abstract mixin class $Event_SeedLockedCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_SeedLockedCopyWith(Event_SeedLocked value, $Res Function(Event_SeedLocked) _then) = _$Event_SeedLockedCopyWithImpl;
@useResult
$Res call({
 String seed
});




}
/// @nodoc
class _$Event_SeedLockedCopyWithImpl<$Res>
    implements $Event_SeedLockedCopyWith<$Res> {
  _$Event_SeedLockedCopyWithImpl(this._self, this._then);

  final Event_SeedLocked _self;
  final $Res Function(Event_SeedLocked) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? seed = null,}) {
  return _then(Event_SeedLocked(
seed: null == seed ? _self.seed : seed // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class Event_KeystoreChanged extends Event {
  const Event_KeystoreChanged({required this.rev}): super._();
  

 final  BigInt rev;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_KeystoreChangedCopyWith<Event_KeystoreChanged> get copyWith => _$Event_KeystoreChangedCopyWithImpl<Event_KeystoreChanged>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_KeystoreChanged&&(identical(other.rev, rev) || other.rev == rev));
}


@override
int get hashCode => Object.hash(runtimeType,rev);

@override
String toString() {
  return 'Event.keystoreChanged(rev: $rev)';
}


}

/// @nodoc
abstract mixin class $Event_KeystoreChangedCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_KeystoreChangedCopyWith(Event_KeystoreChanged value, $Res Function(Event_KeystoreChanged) _then) = _$Event_KeystoreChangedCopyWithImpl;
@useResult
$Res call({
 BigInt rev
});




}
/// @nodoc
class _$Event_KeystoreChangedCopyWithImpl<$Res>
    implements $Event_KeystoreChangedCopyWith<$Res> {
  _$Event_KeystoreChangedCopyWithImpl(this._self, this._then);

  final Event_KeystoreChanged _self;
  final $Res Function(Event_KeystoreChanged) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? rev = null,}) {
  return _then(Event_KeystoreChanged(
rev: null == rev ? _self.rev : rev // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class Event_KeystoreMismatch extends Event {
  const Event_KeystoreMismatch({required this.seed}): super._();
  

 final  String seed;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_KeystoreMismatchCopyWith<Event_KeystoreMismatch> get copyWith => _$Event_KeystoreMismatchCopyWithImpl<Event_KeystoreMismatch>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_KeystoreMismatch&&(identical(other.seed, seed) || other.seed == seed));
}


@override
int get hashCode => Object.hash(runtimeType,seed);

@override
String toString() {
  return 'Event.keystoreMismatch(seed: $seed)';
}


}

/// @nodoc
abstract mixin class $Event_KeystoreMismatchCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_KeystoreMismatchCopyWith(Event_KeystoreMismatch value, $Res Function(Event_KeystoreMismatch) _then) = _$Event_KeystoreMismatchCopyWithImpl;
@useResult
$Res call({
 String seed
});




}
/// @nodoc
class _$Event_KeystoreMismatchCopyWithImpl<$Res>
    implements $Event_KeystoreMismatchCopyWith<$Res> {
  _$Event_KeystoreMismatchCopyWithImpl(this._self, this._then);

  final Event_KeystoreMismatch _self;
  final $Res Function(Event_KeystoreMismatch) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? seed = null,}) {
  return _then(Event_KeystoreMismatch(
seed: null == seed ? _self.seed : seed // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class Event_KeystoreRollback extends Event {
  const Event_KeystoreRollback(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_KeystoreRollback);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'Event.keystoreRollback()';
}


}




/// @nodoc


class Event_HiddenOpsAbandoned extends Event {
  const Event_HiddenOpsAbandoned({required this.count}): super._();
  

 final  int count;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_HiddenOpsAbandonedCopyWith<Event_HiddenOpsAbandoned> get copyWith => _$Event_HiddenOpsAbandonedCopyWithImpl<Event_HiddenOpsAbandoned>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_HiddenOpsAbandoned&&(identical(other.count, count) || other.count == count));
}


@override
int get hashCode => Object.hash(runtimeType,count);

@override
String toString() {
  return 'Event.hiddenOpsAbandoned(count: $count)';
}


}

/// @nodoc
abstract mixin class $Event_HiddenOpsAbandonedCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_HiddenOpsAbandonedCopyWith(Event_HiddenOpsAbandoned value, $Res Function(Event_HiddenOpsAbandoned) _then) = _$Event_HiddenOpsAbandonedCopyWithImpl;
@useResult
$Res call({
 int count
});




}
/// @nodoc
class _$Event_HiddenOpsAbandonedCopyWithImpl<$Res>
    implements $Event_HiddenOpsAbandonedCopyWith<$Res> {
  _$Event_HiddenOpsAbandonedCopyWithImpl(this._self, this._then);

  final Event_HiddenOpsAbandoned _self;
  final $Res Function(Event_HiddenOpsAbandoned) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? count = null,}) {
  return _then(Event_HiddenOpsAbandoned(
count: null == count ? _self.count : count // ignore: cast_nullable_to_non_nullable
as int,
  ));
}


}

/// @nodoc


class Event_Lagged extends Event {
  const Event_Lagged({required this.missed}): super._();
  

 final  BigInt missed;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_LaggedCopyWith<Event_Lagged> get copyWith => _$Event_LaggedCopyWithImpl<Event_Lagged>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_Lagged&&(identical(other.missed, missed) || other.missed == missed));
}


@override
int get hashCode => Object.hash(runtimeType,missed);

@override
String toString() {
  return 'Event.lagged(missed: $missed)';
}


}

/// @nodoc
abstract mixin class $Event_LaggedCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_LaggedCopyWith(Event_Lagged value, $Res Function(Event_Lagged) _then) = _$Event_LaggedCopyWithImpl;
@useResult
$Res call({
 BigInt missed
});




}
/// @nodoc
class _$Event_LaggedCopyWithImpl<$Res>
    implements $Event_LaggedCopyWith<$Res> {
  _$Event_LaggedCopyWithImpl(this._self, this._then);

  final Event_Lagged _self;
  final $Res Function(Event_Lagged) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? missed = null,}) {
  return _then(Event_Lagged(
missed: null == missed ? _self.missed : missed // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class Event_OpState extends Event {
  const Event_OpState({required this.op, required this.state}): super._();
  

 final  String op;
 final  OpState state;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_OpStateCopyWith<Event_OpState> get copyWith => _$Event_OpStateCopyWithImpl<Event_OpState>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_OpState&&(identical(other.op, op) || other.op == op)&&(identical(other.state, state) || other.state == state));
}


@override
int get hashCode => Object.hash(runtimeType,op,state);

@override
String toString() {
  return 'Event.opState(op: $op, state: $state)';
}


}

/// @nodoc
abstract mixin class $Event_OpStateCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_OpStateCopyWith(Event_OpState value, $Res Function(Event_OpState) _then) = _$Event_OpStateCopyWithImpl;
@useResult
$Res call({
 String op, OpState state
});


$OpStateCopyWith<$Res> get state;

}
/// @nodoc
class _$Event_OpStateCopyWithImpl<$Res>
    implements $Event_OpStateCopyWith<$Res> {
  _$Event_OpStateCopyWithImpl(this._self, this._then);

  final Event_OpState _self;
  final $Res Function(Event_OpState) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? op = null,Object? state = null,}) {
  return _then(Event_OpState(
op: null == op ? _self.op : op // ignore: cast_nullable_to_non_nullable
as String,state: null == state ? _self.state : state // ignore: cast_nullable_to_non_nullable
as OpState,
  ));
}

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$OpStateCopyWith<$Res> get state {
  
  return $OpStateCopyWith<$Res>(_self.state, (value) {
    return _then(_self.copyWith(state: value));
  });
}
}

/// @nodoc


class Event_BalanceChanged extends Event {
  const Event_BalanceChanged({required this.account, required this.chain, required this.token}): super._();
  

 final  String account;
 final  String chain;
 final  String token;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_BalanceChangedCopyWith<Event_BalanceChanged> get copyWith => _$Event_BalanceChangedCopyWithImpl<Event_BalanceChanged>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_BalanceChanged&&(identical(other.account, account) || other.account == account)&&(identical(other.chain, chain) || other.chain == chain)&&(identical(other.token, token) || other.token == token));
}


@override
int get hashCode => Object.hash(runtimeType,account,chain,token);

@override
String toString() {
  return 'Event.balanceChanged(account: $account, chain: $chain, token: $token)';
}


}

/// @nodoc
abstract mixin class $Event_BalanceChangedCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_BalanceChangedCopyWith(Event_BalanceChanged value, $Res Function(Event_BalanceChanged) _then) = _$Event_BalanceChangedCopyWithImpl;
@useResult
$Res call({
 String account, String chain, String token
});




}
/// @nodoc
class _$Event_BalanceChangedCopyWithImpl<$Res>
    implements $Event_BalanceChangedCopyWith<$Res> {
  _$Event_BalanceChangedCopyWithImpl(this._self, this._then);

  final Event_BalanceChanged _self;
  final $Res Function(Event_BalanceChanged) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? account = null,Object? chain = null,Object? token = null,}) {
  return _then(Event_BalanceChanged(
account: null == account ? _self.account : account // ignore: cast_nullable_to_non_nullable
as String,chain: null == chain ? _self.chain : chain // ignore: cast_nullable_to_non_nullable
as String,token: null == token ? _self.token : token // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class Event_HistoryAdded extends Event {
  const Event_HistoryAdded({required this.account, required this.chain, required final  List<HistoryItem> items}): _items = items,super._();
  

 final  String account;
 final  String chain;
 final  List<HistoryItem> _items;
 List<HistoryItem> get items {
  if (_items is EqualUnmodifiableListView) return _items;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_items);
}


/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_HistoryAddedCopyWith<Event_HistoryAdded> get copyWith => _$Event_HistoryAddedCopyWithImpl<Event_HistoryAdded>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_HistoryAdded&&(identical(other.account, account) || other.account == account)&&(identical(other.chain, chain) || other.chain == chain)&&const DeepCollectionEquality().equals(other._items, _items));
}


@override
int get hashCode => Object.hash(runtimeType,account,chain,const DeepCollectionEquality().hash(_items));

@override
String toString() {
  return 'Event.historyAdded(account: $account, chain: $chain, items: $items)';
}


}

/// @nodoc
abstract mixin class $Event_HistoryAddedCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_HistoryAddedCopyWith(Event_HistoryAdded value, $Res Function(Event_HistoryAdded) _then) = _$Event_HistoryAddedCopyWithImpl;
@useResult
$Res call({
 String account, String chain, List<HistoryItem> items
});




}
/// @nodoc
class _$Event_HistoryAddedCopyWithImpl<$Res>
    implements $Event_HistoryAddedCopyWith<$Res> {
  _$Event_HistoryAddedCopyWithImpl(this._self, this._then);

  final Event_HistoryAdded _self;
  final $Res Function(Event_HistoryAdded) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? account = null,Object? chain = null,Object? items = null,}) {
  return _then(Event_HistoryAdded(
account: null == account ? _self.account : account // ignore: cast_nullable_to_non_nullable
as String,chain: null == chain ? _self.chain : chain // ignore: cast_nullable_to_non_nullable
as String,items: null == items ? _self._items : items // ignore: cast_nullable_to_non_nullable
as List<HistoryItem>,
  ));
}


}

/// @nodoc


class Event_StateChanged extends Event {
  const Event_StateChanged({required this.rev}): super._();
  

 final  BigInt rev;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Event_StateChangedCopyWith<Event_StateChanged> get copyWith => _$Event_StateChangedCopyWithImpl<Event_StateChanged>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Event_StateChanged&&(identical(other.rev, rev) || other.rev == rev));
}


@override
int get hashCode => Object.hash(runtimeType,rev);

@override
String toString() {
  return 'Event.stateChanged(rev: $rev)';
}


}

/// @nodoc
abstract mixin class $Event_StateChangedCopyWith<$Res> implements $EventCopyWith<$Res> {
  factory $Event_StateChangedCopyWith(Event_StateChanged value, $Res Function(Event_StateChanged) _then) = _$Event_StateChangedCopyWithImpl;
@useResult
$Res call({
 BigInt rev
});




}
/// @nodoc
class _$Event_StateChangedCopyWithImpl<$Res>
    implements $Event_StateChangedCopyWith<$Res> {
  _$Event_StateChangedCopyWithImpl(this._self, this._then);

  final Event_StateChanged _self;
  final $Res Function(Event_StateChanged) _then;

/// Create a copy of Event
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? rev = null,}) {
  return _then(Event_StateChanged(
rev: null == rev ? _self.rev : rev // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc
mixin _$OpState {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is OpState);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'OpState()';
}


}

/// @nodoc
class $OpStateCopyWith<$Res>  {
$OpStateCopyWith(OpState _, $Res Function(OpState) __);
}


/// Adds pattern-matching-related methods to [OpState].
extension OpStatePatterns on OpState {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( OpState_Landed value)?  landed,TResult Function( OpState_Consumed value)?  consumed,TResult Function( OpState_Reverted value)?  reverted,TResult Function( OpState_Expired value)?  expired,TResult Function( OpState_InFlight value)?  inFlight,required TResult orElse(),}){
final _that = this;
switch (_that) {
case OpState_Landed() when landed != null:
return landed(_that);case OpState_Consumed() when consumed != null:
return consumed(_that);case OpState_Reverted() when reverted != null:
return reverted(_that);case OpState_Expired() when expired != null:
return expired(_that);case OpState_InFlight() when inFlight != null:
return inFlight(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( OpState_Landed value)  landed,required TResult Function( OpState_Consumed value)  consumed,required TResult Function( OpState_Reverted value)  reverted,required TResult Function( OpState_Expired value)  expired,required TResult Function( OpState_InFlight value)  inFlight,}){
final _that = this;
switch (_that) {
case OpState_Landed():
return landed(_that);case OpState_Consumed():
return consumed(_that);case OpState_Reverted():
return reverted(_that);case OpState_Expired():
return expired(_that);case OpState_InFlight():
return inFlight(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( OpState_Landed value)?  landed,TResult? Function( OpState_Consumed value)?  consumed,TResult? Function( OpState_Reverted value)?  reverted,TResult? Function( OpState_Expired value)?  expired,TResult? Function( OpState_InFlight value)?  inFlight,}){
final _that = this;
switch (_that) {
case OpState_Landed() when landed != null:
return landed(_that);case OpState_Consumed() when consumed != null:
return consumed(_that);case OpState_Reverted() when reverted != null:
return reverted(_that);case OpState_Expired() when expired != null:
return expired(_that);case OpState_InFlight() when inFlight != null:
return inFlight(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BigInt block,  String hash)?  landed,TResult Function( Basis basis)?  consumed,TResult Function( BigInt block,  String hash)?  reverted,TResult Function( Basis basis)?  expired,TResult Function( InFlight detail)?  inFlight,required TResult orElse(),}) {final _that = this;
switch (_that) {
case OpState_Landed() when landed != null:
return landed(_that.block,_that.hash);case OpState_Consumed() when consumed != null:
return consumed(_that.basis);case OpState_Reverted() when reverted != null:
return reverted(_that.block,_that.hash);case OpState_Expired() when expired != null:
return expired(_that.basis);case OpState_InFlight() when inFlight != null:
return inFlight(_that.detail);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BigInt block,  String hash)  landed,required TResult Function( Basis basis)  consumed,required TResult Function( BigInt block,  String hash)  reverted,required TResult Function( Basis basis)  expired,required TResult Function( InFlight detail)  inFlight,}) {final _that = this;
switch (_that) {
case OpState_Landed():
return landed(_that.block,_that.hash);case OpState_Consumed():
return consumed(_that.basis);case OpState_Reverted():
return reverted(_that.block,_that.hash);case OpState_Expired():
return expired(_that.basis);case OpState_InFlight():
return inFlight(_that.detail);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BigInt block,  String hash)?  landed,TResult? Function( Basis basis)?  consumed,TResult? Function( BigInt block,  String hash)?  reverted,TResult? Function( Basis basis)?  expired,TResult? Function( InFlight detail)?  inFlight,}) {final _that = this;
switch (_that) {
case OpState_Landed() when landed != null:
return landed(_that.block,_that.hash);case OpState_Consumed() when consumed != null:
return consumed(_that.basis);case OpState_Reverted() when reverted != null:
return reverted(_that.block,_that.hash);case OpState_Expired() when expired != null:
return expired(_that.basis);case OpState_InFlight() when inFlight != null:
return inFlight(_that.detail);case _:
  return null;

}
}

}

/// @nodoc


class OpState_Landed extends OpState {
  const OpState_Landed({required this.block, required this.hash}): super._();
  

 final  BigInt block;
 final  String hash;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$OpState_LandedCopyWith<OpState_Landed> get copyWith => _$OpState_LandedCopyWithImpl<OpState_Landed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is OpState_Landed&&(identical(other.block, block) || other.block == block)&&(identical(other.hash, hash) || other.hash == hash));
}


@override
int get hashCode => Object.hash(runtimeType,block,hash);

@override
String toString() {
  return 'OpState.landed(block: $block, hash: $hash)';
}


}

/// @nodoc
abstract mixin class $OpState_LandedCopyWith<$Res> implements $OpStateCopyWith<$Res> {
  factory $OpState_LandedCopyWith(OpState_Landed value, $Res Function(OpState_Landed) _then) = _$OpState_LandedCopyWithImpl;
@useResult
$Res call({
 BigInt block, String hash
});




}
/// @nodoc
class _$OpState_LandedCopyWithImpl<$Res>
    implements $OpState_LandedCopyWith<$Res> {
  _$OpState_LandedCopyWithImpl(this._self, this._then);

  final OpState_Landed _self;
  final $Res Function(OpState_Landed) _then;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? block = null,Object? hash = null,}) {
  return _then(OpState_Landed(
block: null == block ? _self.block : block // ignore: cast_nullable_to_non_nullable
as BigInt,hash: null == hash ? _self.hash : hash // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class OpState_Consumed extends OpState {
  const OpState_Consumed({required this.basis}): super._();
  

 final  Basis basis;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$OpState_ConsumedCopyWith<OpState_Consumed> get copyWith => _$OpState_ConsumedCopyWithImpl<OpState_Consumed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is OpState_Consumed&&(identical(other.basis, basis) || other.basis == basis));
}


@override
int get hashCode => Object.hash(runtimeType,basis);

@override
String toString() {
  return 'OpState.consumed(basis: $basis)';
}


}

/// @nodoc
abstract mixin class $OpState_ConsumedCopyWith<$Res> implements $OpStateCopyWith<$Res> {
  factory $OpState_ConsumedCopyWith(OpState_Consumed value, $Res Function(OpState_Consumed) _then) = _$OpState_ConsumedCopyWithImpl;
@useResult
$Res call({
 Basis basis
});




}
/// @nodoc
class _$OpState_ConsumedCopyWithImpl<$Res>
    implements $OpState_ConsumedCopyWith<$Res> {
  _$OpState_ConsumedCopyWithImpl(this._self, this._then);

  final OpState_Consumed _self;
  final $Res Function(OpState_Consumed) _then;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? basis = null,}) {
  return _then(OpState_Consumed(
basis: null == basis ? _self.basis : basis // ignore: cast_nullable_to_non_nullable
as Basis,
  ));
}


}

/// @nodoc


class OpState_Reverted extends OpState {
  const OpState_Reverted({required this.block, required this.hash}): super._();
  

 final  BigInt block;
 final  String hash;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$OpState_RevertedCopyWith<OpState_Reverted> get copyWith => _$OpState_RevertedCopyWithImpl<OpState_Reverted>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is OpState_Reverted&&(identical(other.block, block) || other.block == block)&&(identical(other.hash, hash) || other.hash == hash));
}


@override
int get hashCode => Object.hash(runtimeType,block,hash);

@override
String toString() {
  return 'OpState.reverted(block: $block, hash: $hash)';
}


}

/// @nodoc
abstract mixin class $OpState_RevertedCopyWith<$Res> implements $OpStateCopyWith<$Res> {
  factory $OpState_RevertedCopyWith(OpState_Reverted value, $Res Function(OpState_Reverted) _then) = _$OpState_RevertedCopyWithImpl;
@useResult
$Res call({
 BigInt block, String hash
});




}
/// @nodoc
class _$OpState_RevertedCopyWithImpl<$Res>
    implements $OpState_RevertedCopyWith<$Res> {
  _$OpState_RevertedCopyWithImpl(this._self, this._then);

  final OpState_Reverted _self;
  final $Res Function(OpState_Reverted) _then;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? block = null,Object? hash = null,}) {
  return _then(OpState_Reverted(
block: null == block ? _self.block : block // ignore: cast_nullable_to_non_nullable
as BigInt,hash: null == hash ? _self.hash : hash // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class OpState_Expired extends OpState {
  const OpState_Expired({required this.basis}): super._();
  

 final  Basis basis;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$OpState_ExpiredCopyWith<OpState_Expired> get copyWith => _$OpState_ExpiredCopyWithImpl<OpState_Expired>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is OpState_Expired&&(identical(other.basis, basis) || other.basis == basis));
}


@override
int get hashCode => Object.hash(runtimeType,basis);

@override
String toString() {
  return 'OpState.expired(basis: $basis)';
}


}

/// @nodoc
abstract mixin class $OpState_ExpiredCopyWith<$Res> implements $OpStateCopyWith<$Res> {
  factory $OpState_ExpiredCopyWith(OpState_Expired value, $Res Function(OpState_Expired) _then) = _$OpState_ExpiredCopyWithImpl;
@useResult
$Res call({
 Basis basis
});




}
/// @nodoc
class _$OpState_ExpiredCopyWithImpl<$Res>
    implements $OpState_ExpiredCopyWith<$Res> {
  _$OpState_ExpiredCopyWithImpl(this._self, this._then);

  final OpState_Expired _self;
  final $Res Function(OpState_Expired) _then;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? basis = null,}) {
  return _then(OpState_Expired(
basis: null == basis ? _self.basis : basis // ignore: cast_nullable_to_non_nullable
as Basis,
  ));
}


}

/// @nodoc


class OpState_InFlight extends OpState {
  const OpState_InFlight({required this.detail}): super._();
  

 final  InFlight detail;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$OpState_InFlightCopyWith<OpState_InFlight> get copyWith => _$OpState_InFlightCopyWithImpl<OpState_InFlight>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is OpState_InFlight&&(identical(other.detail, detail) || other.detail == detail));
}


@override
int get hashCode => Object.hash(runtimeType,detail);

@override
String toString() {
  return 'OpState.inFlight(detail: $detail)';
}


}

/// @nodoc
abstract mixin class $OpState_InFlightCopyWith<$Res> implements $OpStateCopyWith<$Res> {
  factory $OpState_InFlightCopyWith(OpState_InFlight value, $Res Function(OpState_InFlight) _then) = _$OpState_InFlightCopyWithImpl;
@useResult
$Res call({
 InFlight detail
});




}
/// @nodoc
class _$OpState_InFlightCopyWithImpl<$Res>
    implements $OpState_InFlightCopyWith<$Res> {
  _$OpState_InFlightCopyWithImpl(this._self, this._then);

  final OpState_InFlight _self;
  final $Res Function(OpState_InFlight) _then;

/// Create a copy of OpState
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? detail = null,}) {
  return _then(OpState_InFlight(
detail: null == detail ? _self.detail : detail // ignore: cast_nullable_to_non_nullable
as InFlight,
  ));
}


}

// dart format on
