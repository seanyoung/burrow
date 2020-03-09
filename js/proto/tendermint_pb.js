/**
 * @fileoverview
 * @enhanceable
 * @suppress {messageConventions} JS Compiler reports an error if a variable or
 *     field starts with 'MSG_' and isn't a translatable message.
 * @public
 */
// GENERATED CODE -- DO NOT EDIT!

var jspb = require('google-protobuf');
var goog = jspb;
var global = Function('return this')();

var github_com_gogo_protobuf_gogoproto_gogo_pb = require('./github.com/gogo/protobuf/gogoproto/gogo_pb.js');
goog.object.extend(proto, github_com_gogo_protobuf_gogoproto_gogo_pb);
goog.exportSymbol('proto.tendermint.NodeInfo', null, global);
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.tendermint.NodeInfo = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.tendermint.NodeInfo, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.tendermint.NodeInfo.displayName = 'proto.tendermint.NodeInfo';
}



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.tendermint.NodeInfo.prototype.toObject = function(opt_includeInstance) {
  return proto.tendermint.NodeInfo.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.tendermint.NodeInfo} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.tendermint.NodeInfo.toObject = function(includeInstance, msg) {
  var f, obj = {
    id: msg.getId_asB64(),
    listenaddress: jspb.Message.getFieldWithDefault(msg, 2, ""),
    network: jspb.Message.getFieldWithDefault(msg, 3, ""),
    version: jspb.Message.getFieldWithDefault(msg, 4, ""),
    channels: msg.getChannels_asB64(),
    moniker: jspb.Message.getFieldWithDefault(msg, 6, ""),
    rpcaddress: jspb.Message.getFieldWithDefault(msg, 7, ""),
    txindex: jspb.Message.getFieldWithDefault(msg, 8, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.tendermint.NodeInfo}
 */
proto.tendermint.NodeInfo.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.tendermint.NodeInfo;
  return proto.tendermint.NodeInfo.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.tendermint.NodeInfo} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.tendermint.NodeInfo}
 */
proto.tendermint.NodeInfo.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setId(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setListenaddress(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setNetwork(value);
      break;
    case 4:
      var value = /** @type {string} */ (reader.readString());
      msg.setVersion(value);
      break;
    case 5:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setChannels(value);
      break;
    case 6:
      var value = /** @type {string} */ (reader.readString());
      msg.setMoniker(value);
      break;
    case 7:
      var value = /** @type {string} */ (reader.readString());
      msg.setRpcaddress(value);
      break;
    case 8:
      var value = /** @type {string} */ (reader.readString());
      msg.setTxindex(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.tendermint.NodeInfo.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.tendermint.NodeInfo.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.tendermint.NodeInfo} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.tendermint.NodeInfo.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getId_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      1,
      f
    );
  }
  f = message.getListenaddress();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getNetwork();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
  f = message.getVersion();
  if (f.length > 0) {
    writer.writeString(
      4,
      f
    );
  }
  f = message.getChannels_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      5,
      f
    );
  }
  f = message.getMoniker();
  if (f.length > 0) {
    writer.writeString(
      6,
      f
    );
  }
  f = message.getRpcaddress();
  if (f.length > 0) {
    writer.writeString(
      7,
      f
    );
  }
  f = message.getTxindex();
  if (f.length > 0) {
    writer.writeString(
      8,
      f
    );
  }
};


/**
 * optional bytes ID = 1;
 * @return {!(string|Uint8Array)}
 */
proto.tendermint.NodeInfo.prototype.getId = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * optional bytes ID = 1;
 * This is a type-conversion wrapper around `getId()`
 * @return {string}
 */
proto.tendermint.NodeInfo.prototype.getId_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getId()));
};


/**
 * optional bytes ID = 1;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getId()`
 * @return {!Uint8Array}
 */
proto.tendermint.NodeInfo.prototype.getId_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getId()));
};


/** @param {!(string|Uint8Array)} value */
proto.tendermint.NodeInfo.prototype.setId = function(value) {
  jspb.Message.setProto3BytesField(this, 1, value);
};


/**
 * optional string ListenAddress = 2;
 * @return {string}
 */
proto.tendermint.NodeInfo.prototype.getListenaddress = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/** @param {string} value */
proto.tendermint.NodeInfo.prototype.setListenaddress = function(value) {
  jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string Network = 3;
 * @return {string}
 */
proto.tendermint.NodeInfo.prototype.getNetwork = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/** @param {string} value */
proto.tendermint.NodeInfo.prototype.setNetwork = function(value) {
  jspb.Message.setProto3StringField(this, 3, value);
};


/**
 * optional string Version = 4;
 * @return {string}
 */
proto.tendermint.NodeInfo.prototype.getVersion = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 4, ""));
};


/** @param {string} value */
proto.tendermint.NodeInfo.prototype.setVersion = function(value) {
  jspb.Message.setProto3StringField(this, 4, value);
};


/**
 * optional bytes Channels = 5;
 * @return {!(string|Uint8Array)}
 */
proto.tendermint.NodeInfo.prototype.getChannels = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 5, ""));
};


/**
 * optional bytes Channels = 5;
 * This is a type-conversion wrapper around `getChannels()`
 * @return {string}
 */
proto.tendermint.NodeInfo.prototype.getChannels_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getChannels()));
};


/**
 * optional bytes Channels = 5;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getChannels()`
 * @return {!Uint8Array}
 */
proto.tendermint.NodeInfo.prototype.getChannels_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getChannels()));
};


/** @param {!(string|Uint8Array)} value */
proto.tendermint.NodeInfo.prototype.setChannels = function(value) {
  jspb.Message.setProto3BytesField(this, 5, value);
};


/**
 * optional string Moniker = 6;
 * @return {string}
 */
proto.tendermint.NodeInfo.prototype.getMoniker = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/** @param {string} value */
proto.tendermint.NodeInfo.prototype.setMoniker = function(value) {
  jspb.Message.setProto3StringField(this, 6, value);
};


/**
 * optional string RPCAddress = 7;
 * @return {string}
 */
proto.tendermint.NodeInfo.prototype.getRpcaddress = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 7, ""));
};


/** @param {string} value */
proto.tendermint.NodeInfo.prototype.setRpcaddress = function(value) {
  jspb.Message.setProto3StringField(this, 7, value);
};


/**
 * optional string TxIndex = 8;
 * @return {string}
 */
proto.tendermint.NodeInfo.prototype.getTxindex = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 8, ""));
};


/** @param {string} value */
proto.tendermint.NodeInfo.prototype.setTxindex = function(value) {
  jspb.Message.setProto3StringField(this, 8, value);
};


goog.object.extend(exports, proto.tendermint);
