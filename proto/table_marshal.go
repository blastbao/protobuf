// Go support for Protocol Buffers - Google's data interchange format
//
// Copyright 2016 The Go Authors.  All rights reserved.
// https://github.com/golang/protobuf
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package proto

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)



// a sizer takes a pointer to a field and the size of its tag, computes the size of the encoded data.
//
// sizer 需要一个指向某字段的指针和其标签的大小，来计算出编码数据的大小。
type sizer func(pointer, int) int


// a marshaler takes a byte slice, a pointer to a field, and its tag (in wire format),
// marshals the field to the end of the slice, returns the slice and error (if any).
//
// marshaler 接收一个字节切片，一个指向某字段的指针，以及它的标签（wire格式）。
// marshaler 将该字段序列化并追加存入分片的末尾，并返回分片和错误（如果有的话）。
type marshaler func(b []byte, ptr pointer, wiretag uint64, deterministic bool) ([]byte, error)


// marshalInfo is the information used for marshaling a message.
type marshalInfo struct {

	// 对象类型
	typ reflect.Type

	// 各字段的序列化信息
	fields []*marshalFieldInfo

	// 内部字段
	unrecognized field // offset of XXX_unrecognized
	extensions   field // offset of XXX_InternalExtensions
	v1extensions field // offset of XXX_extensions
	sizecache    field // offset of XXX_sizecache

	// 是否已经完成初始化
	initialized int32 // 0 -- only typ is set, 1 -- fully initialized

	//
	messageset bool // uses message set wire format

	// 是否已经实现 marshal 接口
	hasmarshaler bool // has custom marshaler

	// 锁，并发控制
	sync.RWMutex // protect extElems map, also for initialization

	// 扩展元素
	extElems map[int32]*marshalElemInfo // info of extension elements
}

// marshalFieldInfo is the information used for marshaling a field of a message.
//
//
//
//
// #基本编码规则#
//	Protobuf Msg 由字段（field）构成，每个字段有其规则（rule）、数据类型（type）、字段名（name）、tag，以及选项（option）。
// 	在序列化时，field 会按照 tag 顺序，以 key-value 的格式编码成二进制数据，key 也称为 tag 。
//	一个 field 对应一个 key-value 对，整个二进制文件就是一连串紧密排列的 key-value 对。
//
//	可以把序列化之后 data 里的数据想象成下面这样：
//  	data = <k1,v1>|<k2,v2>|<k3,v3>
//
// #数据划分#
//  Protobuf Msg 序列化之后，产生的二进制数据，可以划分为 6 个部分：
// 		MSB flag
//		tag
//		编码后数据类型（wire type）
//		长度（length）
//		字段值（value）
//		以及填充（padding）
//
// #Key#
//	消息的每一个 field ，都会以key+val的形式，序列化为二进制数据。
//	value 比较好猜测，那么 key 具体是什么呢？答案是这样：key = tag << 3 | wire_type ，也就是说 key 的前 3 个比特是 wire type ，剩下的比特是 tag 值。
//
//  3 bit 的 wire_type 最多只能支持8种，目前有 6 种
//
//		Wire Type	Meaning Used For
//		0			Varint int32, int64, uint32, uint64, sint32, sint64, bool, enum
//		1			64-bit fixed64, sfixed64, double
//		2			Length-delimited string, bytes, embedded messages, packed repeated fields
//		3			Start group groups (deprecated)
//		4			End group groups (deprecated)
//		5			32-bit fixed32, sfixed32, float
//
//	Protobuf 支持丰富的数据类型，但是编码之后，只剩下 Varint(0)、64-bit(1)、Length-delimited(2) 和 32-bit(5）这 4 种（还有两种已经废弃了，本文不讨论）类型，
//	用 3 个比特来表示，足够了。
//
//  举例来说：
// 		message Person {
//   		int32 id = 1;
//   		string name = 2;
//   		string email = 3;
//		}
//
//  Person 的 id ，field_number 为 1 ， wire_type 为 0 ，所以对应的 tag 为
//		1 << 3 | 0 = 0x08
//  Person 的 name ，field_number 为 2 ，wire_type 为 2 ，所以对应的 tag 为
//		2 << 3 | 2 = 0x12
//
//
// wire type 被如此设计，主要是为了解决一个问题，如何知道接下来 value 部分的长度（字节数），如果
//	wire type = 0、1、5，编码为 key + 数据，只有一个数据，可能占数个字节，数据在编码时自带终止标记；
//	wire type = 2，编码为 key + length + 数据，length 指示了数据长度，可能有多个数据，顺序排在 length 后；
//
//
//
// Protobuf 中整数是通过 varint 进行编码，移除每个字节的 MSB ，然后拼接在一起，可以得到一个含有数个字节的 buffer ，
// 这个 buffer 该怎么解释还需要参考具体的数据类型。
// 对于 int32 或 int64 ，正数直接按 varint 编码，数据类型为 int32 或 int64 的负数统一被编码为 10 个字节长的 varint（补码）。
// 如果是 sint32 或 sint64 ，则采用 ZigZag 方式进行编码。
//
// Protobuf 中 string、嵌套 message 以及 packed repeated fields，它们的编码方式统一为 tag + length + 数据，只是数据部分有所差异。
//
//

// 对于 int32, int64, uint32 等数据类型在序列化之后都会转为 Varints 编码, 除去两种已标记为 deprecated 的类型,
// 目前 Protobuf 在序列化之后的消息类型(wire-type) 总共有 4 种。
//
// Protobuf 除了存储字段的值之外, 还存储了字段的编号以及字段在通信线路上的格式类型(wire-type), 具体的存储方式为
//   field_num << 3 | wire type
//
// 即将字段标号逻辑左移 3 位, 然后与该字段的 wire type 的编号按位或, 在上表中可以看到, wire type 总共有 6 种类型,
// 因此可以用 3 位二进制来标识, 所以低 3 位实际上存储了其后所跟的数据的 wire type, 接收端可以利用这些信息,
// 结合 proto 文件来解码消息结构体。
//
// 假设 age 为 5, 由于 age 在 proto 文件中定义的是 int32 类型, 因此序列化之后它的 wire type 为 0,
// 其字段编号为 1, 因此按照上面的计算方式, 即 1 << 3 | 0, 所以其类型和字段编号的信息只占 1 个字节,
// 即 00001000, 后面跟上字段值 5 的 Varints 编码, 所以整个结构体序列化之后为
//
// 		00001000 00000101
//      wiretag   value

type marshalFieldInfo struct {



	/// 这三个字段在 setTag() 函数中被设置。

	// 字段的 offset
	field field

	// wiretag = tag(field_num) << 3 | wire_type
	wiretag uint64 // tag in wire format

	// 计算 wiretag 占用的 varint 字节数
	tagsize int // size of tag in wire format


	/// 这三个字段在 setMarshaler() 函数中被设置。

	//
	sizer sizer

	//
	marshaler marshaler

	// 是否是指针
	isPointer bool

	/// 下面字段在 computeMarshalFieldInfo/computeMarshalInfo 中被设置。

	// 是否是必须字段
	required bool // field is required

	// 字段名称
	name string // name of the field, for error reporting

	// xxx
	oneofElems map[reflect.Type]*marshalElemInfo // info of oneof elements
}

// marshalElemInfo is the information used for marshaling an extension or oneof element.
type marshalElemInfo struct {
	wiretag   uint64 // tag in wire format
	tagsize   int    // size of tag in wire format
	sizer     sizer
	marshaler marshaler
	isptr     bool // elem is pointer typed, thus interface of this type is a direct interface (extension only)
	deref     bool // dereference the pointer before operating on it; implies isptr
}

var (
	marshalInfoMap  = map[reflect.Type]*marshalInfo{}
	marshalInfoLock sync.Mutex
)

// getMarshalInfo returns the information to marshal a given type of message.
// The info it returns may not necessarily initialized.
// t is the type of the message (NOT the pointer to it).
//
// 获取 MarshalInfo 结构体，如果不存在则使用 message 类型 t 创建 1 个并返回。
func getMarshalInfo(t reflect.Type) *marshalInfo {
	marshalInfoLock.Lock()
	u, ok := marshalInfoMap[t]
	if !ok {
		// 构造新的空 marshalInfo ，保存 t 的序列化信息
		u = &marshalInfo{
			typ: t,	// 只需要传入 t 即可获得该对象的所有信息
		}
		marshalInfoMap[t] = u
	}
	marshalInfoLock.Unlock()
	return u
}

// Size is the entry point from generated code, and should be ONLY called by generated code.
// It computes the size of encoded data of msg.
// a is a pointer to a place to store cached marshal info.
//
// Size 是生成代码的入口点，应该只由生成代码调用。
// Size 计算 msg 的编码数据的大小。
//
// a 是一个指针，用于存储缓存的 marshal 信息。
func (a *InternalMessageInfo) Size(msg Message) int {



	u := getMessageMarshalInfo(msg, a)

	ptr := toPointer(&msg)
	if ptr.isNil() {
		// We get here if msg is a typed nil ((*SomeMessage)(nil)),
		// so it satisfies the interface, and msg == nil wouldn't
		// catch it. We don't want crash in this case.
		return 0
	}

	return u.size(ptr)
}

// Marshal is the entry point from generated code, and should be ONLY called by generated code.
// It marshals msg to the end of b.
// a is a pointer to a place to store cached marshal info.
//
// InternalMessageInfo.Marshal 首先是获取待序列化类型的序列化信息 u marshalInfo，然后利用 u.marshal 进行序列化。
func (a *InternalMessageInfo) Marshal(b []byte, msg Message, deterministic bool) ([]byte, error) {

	// 获取该 message 类型的 MarshalInfo ，这些信息都缓存起来，大量并发时无需重复创建
	u := getMessageMarshalInfo(msg, a)

	// 入参校验: 检查是否为 nil
	ptr := toPointer(&msg)
	if ptr.isNil() {
		// We get here if msg is a typed nil ((*SomeMessage)(nil)),
		// so it satisfies the interface, and msg == nil wouldn't
		// catch it. We don't want crash in this case.
		return b, ErrNil
	}

	// 根据 MarshalInfo 对数据进行 marshal
	return u.marshal(b, ptr, deterministic)
}

// 每种类型的序列化信息是一致的，以 getMessageMarshalInfo 对序列化信息进行了缓存，缓存在 a.marshal 中，
// 如果 a 中不存在 marshal 信息，则去生成，但不进行初始化，然后保存到 a 中。
func getMessageMarshalInfo(msg interface{}, a *InternalMessageInfo) *marshalInfo {

	// u := a.marshal, but atomically.
	// We use an atomic here to ensure memory consistency.
	//
	// 获取 marshalInfo
	u := atomicLoadMarshalInfo(&a.marshal)

	// 读取不到代表未保存过
	if u == nil {

		// Get marshal information from type of message.

		// 获取 msg 的真实类型
		t := reflect.ValueOf(msg).Type()

		// 要求 msg 类型必须是指针
		if t.Kind() != reflect.Ptr {
			panic(fmt.Sprintf("cannot handle non-pointer message type %v", t))
		}

		// 根据 msg 类型创建 MarshalInfo 对象
		u = getMarshalInfo(t.Elem())

		// Store it in the cache for later users.
		// a.marshal = u, but atomically.
		atomicStoreMarshalInfo(&a.marshal, u)

	}

	return u
}

// size is the main function to compute the size of the encoded data of a message.
// ptr is the pointer to the message.
func (u *marshalInfo) size(ptr pointer) int {

	// 未初始化则初始化一下
	if atomic.LoadInt32(&u.initialized) == 0 {
		u.computeMarshalInfo()
	}

	// If the message can marshal itself, let it do it, for compatibility.
	// NOTE: This is not efficient.
	//
	// 检查是否已经实现 marshal() 接口
	if u.hasmarshaler {
		m := ptr.asPointerTo(u.typ).Interface().(Marshaler)
		b, _ := m.Marshal()
		return len(b)
	}


	// 遍历所有 field ，统计总 size 。
	n := 0
	for _, f := range u.fields {
		// 空指针则不会被序列化
		if f.isPointer && ptr.offset(f.field).getPointer().isNil() {
			// nil pointer always marshals to nothing
			continue
		}
		// 计算当前 field 的 size
		n += f.sizer(ptr.offset(f.field), f.tagsize)
	}

	// 扩展字段
	if u.extensions.IsValid() {
		e := ptr.offset(u.extensions).toExtensions()
		if u.messageset {
			n += u.sizeMessageSet(e)
		} else {
			n += u.sizeExtensions(e)
		}
	}

	// 扩展字段
	if u.v1extensions.IsValid() {
		m := *ptr.offset(u.v1extensions).toOldExtensions()
		n += u.sizeV1Extensions(m)
	}

	// 未识别字段
	if u.unrecognized.IsValid() {
		s := *ptr.offset(u.unrecognized).toBytes()
		n += len(s)
	}

	// cache the result for use in marshal
	// 是否需要缓存 size
	if u.sizecache.IsValid() {
		atomic.StoreInt32(ptr.offset(u.sizecache).toInt32(), int32(n))
	}

	return n
}

// cachedsize gets the size from cache.
// If there is no cache (i.e. message is not generated), fall back to compute the size.
func (u *marshalInfo) cachedsize(ptr pointer) int {
	if u.sizecache.IsValid() {
		return int(atomic.LoadInt32(ptr.offset(u.sizecache).toInt32()))
	}
	return u.size(ptr)
}

// marshal is the main function to marshal a message. It takes a byte slice and appends
// the encoded data to the end of the slice, returns the slice and error (if any).
// ptr is the pointer to the message.
//
// If deterministic is true, map is marshaled in deterministic order.
// 如果 deterministic 为 true ，则 map 序列化时会保持原始顺序。
//
//
//
// 该函数是 Marshal 的主体函数，把消息编码为数据后，追加到 b 之后，最后返回 b 。
// deterministic 为 true 代表 map 会以确定的顺序进行编码。
//
/// marshalInfo.marshal 是 Marshal 真实主体，会判断 u 是否已经初始化，
// 如果未初始化调用 computeMarshalInfo 计算 Marshal 需要的信息，实际就是填充 marshalInfo 中的各种字段。
//
// u.hasmarshaler 代表当前类型是否实现了 Marshaler 接口，直接调用 Marshal 函数进行序列化。
// 可以确定 Marshal函 数的序列化方式2，即实现 Marshaler 接口的方法，最后肯定也会调用 marshalInfo.marshal 。
//
// 该函数的主体是一个 for 循环，依次遍历该类型的每一个字段，对 required 属性进行校验，然后按字段类型，
// 调用 f.marshaler 对该字段类型进行序列化。
//
// 这个 f.marshaler 哪来的呢？

func (u *marshalInfo) marshal(b []byte, ptr pointer, deterministic bool) ([]byte, error) {

	// 初始化 marshalInfo 的基础信息，主要是根据已有信息填充该结构体的一些字段
	if atomic.LoadInt32(&u.initialized) == 0 {
		// 执行初始化
		u.computeMarshalInfo()
	}

	// If the message can marshal itself, let it do it, for compatibility.
	// NOTE: This is not efficient.
	//
	// 如果该类型实现了 Marshaler 接口，即能够对自己 Marshal ，则自行 Marshal ，然后将结果追加到 b 。
	if u.hasmarshaler {
		m := ptr.asPointerTo(u.typ).Interface().(Marshaler)
		b1, err := m.Marshal()
		b = append(b, b1...)
		return b, err
	}

	var err, errLater error

	// The old marshaler encodes extensions at beginning.
	// 检查扩展字段，把 message 的扩展字段追加到b
	if u.extensions.IsValid() {
		// offset 函数用来根据指针偏移量获取 message 的指定字段
		e := ptr.offset(u.extensions).toExtensions()
		if u.messageset {
			b, err = u.appendMessageSet(b, e, deterministic)
		} else {
			b, err = u.appendExtensions(b, e, deterministic)
		}
		if err != nil {
			return b, err
		}
	}

	if u.v1extensions.IsValid() {
		m := *ptr.offset(u.v1extensions).toOldExtensions()
		b, err = u.appendV1Extensions(b, m, deterministic)
		if err != nil {
			return b, err
		}
	}

	// 遍历 message 的每一个字段，检查并做编码，然后追加到 b 。
	for _, f := range u.fields {

		// 为 required 类型字段，检查是否为空
		if f.required {
			// 为空则记录错误，所有的 marshal 工作完成后再处理
			if ptr.offset(f.field).getPointer().isNil() {
				// Required field is not set.
				// We record the error but keep going, to give a complete marshaling.
				if errLater == nil {
					errLater = &RequiredNotSetError{f.name}
				}
				continue
			}
		}

		// 字段为指针类型，并且为 nil ，代表未设置，则该字段无需编码
		if f.isPointer && ptr.offset(f.field).getPointer().isNil() {
			// nil pointer always marshals to nothing
			continue
		}

		// 利用这个字段的 marshaler 进行编码
		b, err = f.marshaler(b, ptr.offset(f.field), f.wiretag, deterministic)
		if err != nil {

			// required 字段未设置
			if err1, ok := err.(*RequiredNotSetError); ok {
				// Required field in submessage is not set.
				// We record the error but keep going, to give a complete marshaling.
				//
				// required 字段未设置，暂时记录下错误，以便能够得到完整的错误信息。
				if errLater == nil {
					errLater = &RequiredNotSetError{f.name + "." + err1.field}
				}
				continue
			}

			// “动态数组” 中包含 nil 元素
			if err == errRepeatedHasNil {
				err = errors.New("proto: repeated field " + f.name + " has nil element")
			}

			// 非 utf-8 编码
			if err == errInvalidUTF8 {
				if errLater == nil {
					fullName := revProtoTypes[reflect.PtrTo(u.typ)] + "." + f.name
					errLater = &invalidUTF8Error{fullName}
				}
				continue
			}

			// 其它错误，返回
			return b, err
		}
	}

	// 未识别的类型字段，直接转为 bytes ，追加到 b ，在 computeMarshalInfo 中已经收集这些字段。
	if u.unrecognized.IsValid() {
		s := *ptr.offset(u.unrecognized).toBytes()
		b = append(b, s...)
	}

	//
	return b, errLater
}

// computeMarshalInfo initializes the marshal info.
//
// 回顾一下 Request 的定义，它包含 1 个字段 Data ，后面 `protobuf:...` 描述了 protobuf 要使用的信息，"bytes,..." 这段被称为 tags ，用逗号进行分割后，其中：
//
// 	tags[0]: bytes，代表 Data 类型的数据要被转换为bytes
//	tags[1]: 1，代表了字段的ID
//	tags[2]: opt，代表非必须
//	tags[3]: name=data，proto 文件中的名称
//	tags[4]: proto3，代表使用的protobuf版本
//
// // request.pb.go
// type Request struct{
//    Data                 string   `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
//    ...
// }
//
// computeMarshalInfo 实际上就是对要序列化的类型，进行一次全面检查，设置好序列化要使用的数据，
// 这其中就包含了各字段的序列化函数 f.marshaler 。
//
// 我们重点关注下这部分，struct 的每一个字段都会分配一个 marshalFieldInfo ，代表这个字段序列化需要的信息，
// 会调用 computeMarshalFieldInfo 会填充这个对象。
//
func (u *marshalInfo) computeMarshalInfo() {

	// 加锁，代表了不能同时计算 marshal 信息
	u.Lock()
	defer u.Unlock()

	// 计算 1 次即可
	if u.initialized != 0 { // non-atomic read is ok as it is protected by the lock
		return
	}

	// 获取要 marshal 的 message 类型
	t := u.typ


	u.unrecognized = invalidField
	u.extensions = invalidField
	u.v1extensions = invalidField
	u.sizecache = invalidField

	// If the message can marshal itself, let it do it, for compatibility.
	// NOTE: This is not efficient.
	//
	// 判断当前类型是否实现了 Marshal 接口，如果实现标记为类型自有 marshaler 。
	// 备注：没用类型断言是因为 t 是 Type 类型，不是保存在某个接口的变量
	if reflect.PtrTo(t).Implements(marshalerType) {
		u.hasmarshaler = true
		atomic.StoreInt32(&u.initialized, 1)
		// 可以直接返回了，后面使用自有的 marshaler 编码
		return
	}

	// get oneof implementers
	// 看 *t 实现了以下哪个接口，oneof 特性
	var oneofImplementers []interface{}
	switch m := reflect.Zero(reflect.PtrTo(t)).Interface().(type) {
	case oneofFuncsIface:
		_, _, _, oneofImplementers = m.XXX_OneofFuncs()
	case oneofWrappersIface:
		oneofImplementers = m.XXX_OneofWrappers()
	}

	// 字段总数
	n := t.NumField()

	// deal with XXX fields first
	// 遍历 t 的每一个 XXX 字段
	for i := 0; i < t.NumField(); i++ {

		// 取当前字段
		f := t.Field(i)

		// 跳过非 XXX 开头的字段
		if !strings.HasPrefix(f.Name, "XXX_") {
			continue
		}

		// 处理以下几个 protobuf 自带的字段
		switch f.Name {
		case "XXX_sizecache":
			u.sizecache = toField(&f)
		case "XXX_unrecognized":
			u.unrecognized = toField(&f)
		case "XXX_InternalExtensions":
			u.extensions = toField(&f)
			u.messageset = f.Tag.Get("protobuf_messageset") == "1"
		case "XXX_extensions":
			u.v1extensions = toField(&f)
		case "XXX_NoUnkeyedLiteral":
			// nothing to do
		default:
			panic("unknown XXX field: " + f.Name)
		}
		n--
	}

	// normal fields
	//
	// 处理 message 的普通字段

	fields := make([]marshalFieldInfo, n) // batch allocation
	u.fields = make([]*marshalFieldInfo, 0, n)
	for i, j := 0, 0; i < t.NumField(); i++ {
		// 取当前字段
		f := t.Field(i)

		// 跳过 XXX 字段
		if strings.HasPrefix(f.Name, "XXX_") {
			continue
		}

		// 取 fields 的下一个有效字段，指针类型
		// j 代表了 fields 有效字段数量，n 是包含了 XXX 字段的总字段数量
		field := &fields[j]
		j++

		// 填充字段名称
		field.name = f.Name

		// 填充到 u.fields
		u.fields = append(u.fields, field)

		// 字段的 tag 里包含 “protobuf_oneof” 特殊处理
		if f.Tag.Get("protobuf_oneof") != "" {
			field.computeOneofFieldInfo(&f, oneofImplementers)
			continue
		}

		// 字段里不包含 “protobuf” ，代表不是 protoc 自动生成的字段
		if f.Tag.Get("protobuf") == "" {
			// field has no tag (not in generated message), ignore it
			// 删除刚刚保存的字段信息
			u.fields = u.fields[:len(u.fields)-1]
			j--
			continue
		}

		// 填充字段的 marshal 信息
		field.computeMarshalFieldInfo(&f)

	}

	// fields are marshaled in tag order on the wire.
	// 根据 tag 对字段排序
	sort.Sort(byTag(u.fields))

	// 初始化完成
	atomic.StoreInt32(&u.initialized, 1)
}

// helper for sorting fields by tag
type byTag []*marshalFieldInfo

func (a byTag) Len() int           { return len(a) }
func (a byTag) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byTag) Less(i, j int) bool { return a[i].wiretag < a[j].wiretag }

// getExtElemInfo returns the information to marshal an extension element.
// The info it returns is initialized.
func (u *marshalInfo) getExtElemInfo(desc *ExtensionDesc) *marshalElemInfo {

	// get from cache first
	u.RLock()
	e, ok := u.extElems[desc.Field]
	u.RUnlock()

	if ok {
		return e
	}

	t := reflect.TypeOf(desc.ExtensionType) // pointer or slice to basic type or struct
	tags := strings.Split(desc.Tag, ",")
	tag, err := strconv.Atoi(tags[1])
	if err != nil {
		panic("tag is not an integer")
	}
	wt := wiretype(tags[0])
	if t.Kind() == reflect.Ptr && t.Elem().Kind() != reflect.Struct {
		t = t.Elem()
	}
	sizer, marshaler := typeMarshaler(t, tags, false, false)
	var deref bool
	if t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8 {
		t = reflect.PtrTo(t)
		deref = true
	}
	e = &marshalElemInfo{
		wiretag:   uint64(tag)<<3 | wt,
		tagsize:   SizeVarint(uint64(tag) << 3),
		sizer:     sizer,
		marshaler: marshaler,
		isptr:     t.Kind() == reflect.Ptr,
		deref:     deref,
	}

	// update cache
	u.Lock()
	if u.extElems == nil {
		u.extElems = make(map[int32]*marshalElemInfo)
	}
	u.extElems[desc.Field] = e
	u.Unlock()
	return e
}

// computeMarshalFieldInfo fills up the information to marshal a field.
func (fi *marshalFieldInfo) computeMarshalFieldInfo(f *reflect.StructField) {

	// parse protobuf tag of the field.
	// tag has format of "bytes,49,opt,name=foo,def=hello!"
	//
	// 获取 "protobuf" 的完整tag，然后使用 "," 分割
	tags := strings.Split(f.Tag.Get("protobuf"), ",")
	if tags[0] == "" {
		return
	}

	// tag 编号，即 message 中设置的 string name = x，则 x 就是这个字段的 tag id 。
	tag, err := strconv.Atoi(tags[1])
	if err != nil {
		panic("tag is not an integer")
	}

	// 要转换成的类型：bytes，varint 等，目前只有 5 种 wire type
	wt := wiretype(tags[0])

	// 设置字段是 required 还是 optional
	if tags[2] == "req" {
		fi.required = true
	}

	// 设置 field 和 tag 信息到 marshalFieldInfo
	fi.setTag(f, tag, wt)

	// 根据当前的 tag 信息（类型等），选择 marshaler 函数
	fi.setMarshaler(f, tags)
}

func (fi *marshalFieldInfo) computeOneofFieldInfo(f *reflect.StructField, oneofImplementers []interface{}) {

	// 保存字段信息
	fi.field = toField(f)
	fi.wiretag = math.MaxInt32 // Use a large tag number, make oneofs sorted at the end. This tag will not appear on the wire.
	fi.isPointer = true
	fi.sizer, fi.marshaler = makeOneOfMarshaler(fi, f)
	fi.oneofElems = make(map[reflect.Type]*marshalElemInfo)

	// 字段 f 是接口类型
	ityp := f.Type // interface type

	//
	for _, o := range oneofImplementers {

		t := reflect.TypeOf(o)

		// 检查 o 是否实现了 ityp 接口
		if !t.Implements(ityp) {
			continue
		}

		// 获取字段
		sf := t.Elem().Field(0) // oneof implementer is a struct with a single field

		// 获取 tags
		tags := strings.Split(sf.Tag.Get("protobuf"), ",")
		tag, err := strconv.Atoi(tags[1])
		if err != nil {
			panic("tag is not an integer")
		}

		// 获取 wiretype
		wt := wiretype(tags[0])

		// 获取字段 sf 的 sizer, marshaler
		sizer, marshaler := typeMarshaler(sf.Type, tags, false, true) // oneof should not omit any zero value

		// ...
		fi.oneofElems[t.Elem()] = &marshalElemInfo{
			wiretag:   uint64(tag)<<3 | wt,
			tagsize:   SizeVarint(uint64(tag) << 3),
			sizer:     sizer,
			marshaler: marshaler,
		}

	}
}

// wiretype returns the wire encoding of the type.
//
// 目前只有 5 中 wire type
func wiretype(encoding string) uint64 {
	switch encoding {
	case "fixed32":
		return WireFixed32
	case "fixed64":
		return WireFixed64
	case "varint", "zigzag32", "zigzag64":
		return WireVarint
	case "bytes":
		return WireBytes
	case "group":
		return WireStartGroup
	}
	panic("unknown wire type " + encoding)
}

// setTag fills up the tag (in wire format) and its size in the info of a field.
func (fi *marshalFieldInfo) setTag(f *reflect.StructField, tag int, wireType uint64) {

	// 把 struct.offset 转换成 filed
	fi.field = toField(f)

	// key = tag(field_num) << 3 | wire_type ，也就是说 key 的前 3 个比特是 wire type ，剩下的比特是 tag 值。
	fi.wiretag = uint64(tag)<<3 | wireType

	// 计算 wiretag 占用的 varint 字节数
	fi.tagsize = SizeVarint(uint64(tag) << 3)
}

// setMarshaler fills up the sizer and marshaler in the info of a field.
func (fi *marshalFieldInfo) setMarshaler(f *reflect.StructField, tags []string) {
	switch f.Type.Kind() {
	// map 类型字段特殊处理
	case reflect.Map:
		// map field
		fi.isPointer = true
		fi.sizer, fi.marshaler = makeMapMarshaler(f)
		return
	// 指针字段和切片字段标记指针类型
	case reflect.Ptr, reflect.Slice:
		fi.isPointer = true
	}

	// 根据字段类型和 tag 选择 marshaler
	fi.sizer, fi.marshaler = typeMarshaler(f.Type, tags, true, false)
}

// typeMarshaler returns the sizer and marshaler of a given field.
// t is the type of the field.
// tags is the generated "protobuf" tag of the field.
//
// If nozero is true, zero value is not marshaled to the wire.
// If oneof is true, it is a oneof field.
//
// 如果 nozero 为 true ，则零值不会被序列化。
// 如果 oneof 为 true ，意味着当前字段为 oneof 字段。
func typeMarshaler(t reflect.Type, tags []string, nozero, oneof bool) (sizer, marshaler) {

	// 获取 wiretype
	encoding := tags[0]

	// 是否是指针
	pointer := false

	// 是否是切片
	slice := false

	// 如果是切片类型，解引用
	if t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8 {
		slice = true
		t = t.Elem()
	}

	// 如果是指针类型，解引用
	if t.Kind() == reflect.Ptr {
		pointer = true
		t = t.Elem()
	}

	// 是否是 packed 类型
	packed := false

	// 是否是 proto3 类型
	proto3 := false

	// 是否需要对字符串验证 utf-8
	validateUTF8 := true

	for i := 2; i < len(tags); i++ {
		if tags[i] == "packed" {
			packed = true
		}
		if tags[i] == "proto3" {
			proto3 = true
		}
	}

	validateUTF8 = validateUTF8 && proto3


	switch t.Kind() {
	case reflect.Bool:

		// 指针类型
		if pointer {
			return sizeBoolPtr, appendBoolPtr
		}

		// 切片类型
		if slice {
			// 如果是 packed 类型
			if packed {
				return sizeBoolPackedSlice, appendBoolPackedSlice
			}
			return sizeBoolSlice, appendBoolSlice
		}

		// 忽略零值
		if nozero {
			return sizeBoolValueNoZero, appendBoolValueNoZero
		}

		return sizeBoolValue, appendBoolValue
	case reflect.Uint32:
		switch encoding {
		case "fixed32":
			if pointer {
				return sizeFixed32Ptr, appendFixed32Ptr
			}
			if slice {
				if packed {
					return sizeFixed32PackedSlice, appendFixed32PackedSlice
				}
				return sizeFixed32Slice, appendFixed32Slice
			}
			if nozero {
				return sizeFixed32ValueNoZero, appendFixed32ValueNoZero
			}
			return sizeFixed32Value, appendFixed32Value
		case "varint":
			if pointer {
				return sizeVarint32Ptr, appendVarint32Ptr
			}
			if slice {
				if packed {
					return sizeVarint32PackedSlice, appendVarint32PackedSlice
				}
				return sizeVarint32Slice, appendVarint32Slice
			}
			if nozero {
				return sizeVarint32ValueNoZero, appendVarint32ValueNoZero
			}
			return sizeVarint32Value, appendVarint32Value
		}
	case reflect.Int32:
		switch encoding {
		case "fixed32":
			if pointer {
				return sizeFixedS32Ptr, appendFixedS32Ptr
			}
			if slice {
				if packed {
					return sizeFixedS32PackedSlice, appendFixedS32PackedSlice
				}
				return sizeFixedS32Slice, appendFixedS32Slice
			}
			if nozero {
				return sizeFixedS32ValueNoZero, appendFixedS32ValueNoZero
			}
			return sizeFixedS32Value, appendFixedS32Value
		case "varint":
			if pointer {
				return sizeVarintS32Ptr, appendVarintS32Ptr
			}
			if slice {
				if packed {
					return sizeVarintS32PackedSlice, appendVarintS32PackedSlice
				}
				return sizeVarintS32Slice, appendVarintS32Slice
			}
			if nozero {
				return sizeVarintS32ValueNoZero, appendVarintS32ValueNoZero
			}
			return sizeVarintS32Value, appendVarintS32Value
		case "zigzag32":
			if pointer {
				return sizeZigzag32Ptr, appendZigzag32Ptr
			}
			if slice {
				if packed {
					return sizeZigzag32PackedSlice, appendZigzag32PackedSlice
				}
				return sizeZigzag32Slice, appendZigzag32Slice
			}
			if nozero {
				return sizeZigzag32ValueNoZero, appendZigzag32ValueNoZero
			}
			return sizeZigzag32Value, appendZigzag32Value
		}
	case reflect.Uint64:
		switch encoding {
		case "fixed64":
			if pointer {
				return sizeFixed64Ptr, appendFixed64Ptr
			}
			if slice {
				if packed {
					return sizeFixed64PackedSlice, appendFixed64PackedSlice
				}
				return sizeFixed64Slice, appendFixed64Slice
			}
			if nozero {
				return sizeFixed64ValueNoZero, appendFixed64ValueNoZero
			}
			return sizeFixed64Value, appendFixed64Value
		case "varint":
			if pointer {
				return sizeVarint64Ptr, appendVarint64Ptr
			}
			if slice {
				if packed {
					return sizeVarint64PackedSlice, appendVarint64PackedSlice
				}
				return sizeVarint64Slice, appendVarint64Slice
			}
			if nozero {
				return sizeVarint64ValueNoZero, appendVarint64ValueNoZero
			}
			return sizeVarint64Value, appendVarint64Value
		}
	case reflect.Int64:
		switch encoding {
		case "fixed64":
			if pointer {
				return sizeFixedS64Ptr, appendFixedS64Ptr
			}
			if slice {
				if packed {
					return sizeFixedS64PackedSlice, appendFixedS64PackedSlice
				}
				return sizeFixedS64Slice, appendFixedS64Slice
			}
			if nozero {
				return sizeFixedS64ValueNoZero, appendFixedS64ValueNoZero
			}
			return sizeFixedS64Value, appendFixedS64Value
		case "varint":
			if pointer {
				return sizeVarintS64Ptr, appendVarintS64Ptr
			}
			if slice {
				if packed {
					return sizeVarintS64PackedSlice, appendVarintS64PackedSlice
				}
				return sizeVarintS64Slice, appendVarintS64Slice
			}
			if nozero {
				return sizeVarintS64ValueNoZero, appendVarintS64ValueNoZero
			}
			return sizeVarintS64Value, appendVarintS64Value
		case "zigzag64":
			if pointer {
				return sizeZigzag64Ptr, appendZigzag64Ptr
			}
			if slice {
				if packed {
					return sizeZigzag64PackedSlice, appendZigzag64PackedSlice
				}
				return sizeZigzag64Slice, appendZigzag64Slice
			}
			if nozero {
				return sizeZigzag64ValueNoZero, appendZigzag64ValueNoZero
			}
			return sizeZigzag64Value, appendZigzag64Value
		}
	case reflect.Float32:
		if pointer {
			return sizeFloat32Ptr, appendFloat32Ptr
		}
		if slice {
			if packed {
				return sizeFloat32PackedSlice, appendFloat32PackedSlice
			}
			return sizeFloat32Slice, appendFloat32Slice
		}
		if nozero {
			return sizeFloat32ValueNoZero, appendFloat32ValueNoZero
		}
		return sizeFloat32Value, appendFloat32Value
	case reflect.Float64:
		if pointer {
			return sizeFloat64Ptr, appendFloat64Ptr
		}
		if slice {
			if packed {
				return sizeFloat64PackedSlice, appendFloat64PackedSlice
			}
			return sizeFloat64Slice, appendFloat64Slice
		}
		if nozero {
			return sizeFloat64ValueNoZero, appendFloat64ValueNoZero
		}
		return sizeFloat64Value, appendFloat64Value
	case reflect.String:
		//
		if validateUTF8 {
			if pointer {
				return sizeStringPtr, appendUTF8StringPtr
			}
			if slice {
				return sizeStringSlice, appendUTF8StringSlice
			}
			if nozero {
				return sizeStringValueNoZero, appendUTF8StringValueNoZero
			}
			return sizeStringValue, appendUTF8StringValue
		}

		if pointer {
			return sizeStringPtr, appendStringPtr
		}
		if slice {
			return sizeStringSlice, appendStringSlice
		}
		if nozero {
			return sizeStringValueNoZero, appendStringValueNoZero
		}
		return sizeStringValue, appendStringValue
	case reflect.Slice:
		if slice {
			return sizeBytesSlice, appendBytesSlice
		}
		if oneof {
			// Oneof bytes field may also have "proto3" tag.
			// We want to marshal it as a oneof field. Do this
			// check before the proto3 check.
			return sizeBytesOneof, appendBytesOneof
		}
		if proto3 {
			return sizeBytes3, appendBytes3
		}
		return sizeBytes, appendBytes
	case reflect.Struct:
		switch encoding {
		case "group":
			if slice {
				return makeGroupSliceMarshaler(getMarshalInfo(t))
			}
			return makeGroupMarshaler(getMarshalInfo(t))
		case "bytes":
			if slice {
				return makeMessageSliceMarshaler(getMarshalInfo(t))
			}
			return makeMessageMarshaler(getMarshalInfo(t))
		}
	}
	panic(fmt.Sprintf("unknown or mismatched type: type: %v, wire type: %v", t, encoding))
}

// Below are functions to size/marshal a specific type of a field.
// They are stored in the field's info, and called by function pointers.
// They have type sizer or marshaler.

func sizeFixed32Value(_ pointer, tagsize int) int {
	return 4 + tagsize
}
func sizeFixed32ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toUint32()
	if v == 0 {
		return 0
	}
	return 4 + tagsize
}
func sizeFixed32Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toUint32Ptr()
	if p == nil {
		return 0
	}
	return 4 + tagsize
}
func sizeFixed32Slice(ptr pointer, tagsize int) int {
	s := *ptr.toUint32Slice()
	return (4 + tagsize) * len(s)
}
func sizeFixed32PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toUint32Slice()
	if len(s) == 0 {
		return 0
	}
	return 4*len(s) + SizeVarint(uint64(4*len(s))) + tagsize
}
func sizeFixedS32Value(_ pointer, tagsize int) int {
	return 4 + tagsize
}
func sizeFixedS32ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toInt32()
	if v == 0 {
		return 0
	}
	return 4 + tagsize
}
func sizeFixedS32Ptr(ptr pointer, tagsize int) int {
	p := ptr.getInt32Ptr()
	if p == nil {
		return 0
	}
	return 4 + tagsize
}
func sizeFixedS32Slice(ptr pointer, tagsize int) int {
	s := ptr.getInt32Slice()
	return (4 + tagsize) * len(s)
}
func sizeFixedS32PackedSlice(ptr pointer, tagsize int) int {
	s := ptr.getInt32Slice()
	if len(s) == 0 {
		return 0
	}
	return 4*len(s) + SizeVarint(uint64(4*len(s))) + tagsize
}
func sizeFloat32Value(_ pointer, tagsize int) int {
	return 4 + tagsize
}
func sizeFloat32ValueNoZero(ptr pointer, tagsize int) int {
	v := math.Float32bits(*ptr.toFloat32())
	if v == 0 {
		return 0
	}
	return 4 + tagsize
}
func sizeFloat32Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toFloat32Ptr()
	if p == nil {
		return 0
	}
	return 4 + tagsize
}
func sizeFloat32Slice(ptr pointer, tagsize int) int {
	s := *ptr.toFloat32Slice()
	return (4 + tagsize) * len(s)
}
func sizeFloat32PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toFloat32Slice()
	if len(s) == 0 {
		return 0
	}
	return 4*len(s) + SizeVarint(uint64(4*len(s))) + tagsize
}
func sizeFixed64Value(_ pointer, tagsize int) int {
	return 8 + tagsize
}
func sizeFixed64ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toUint64()
	if v == 0 {
		return 0
	}
	return 8 + tagsize
}
func sizeFixed64Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toUint64Ptr()
	if p == nil {
		return 0
	}
	return 8 + tagsize
}
func sizeFixed64Slice(ptr pointer, tagsize int) int {
	s := *ptr.toUint64Slice()
	return (8 + tagsize) * len(s)
}
func sizeFixed64PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toUint64Slice()
	if len(s) == 0 {
		return 0
	}
	return 8*len(s) + SizeVarint(uint64(8*len(s))) + tagsize
}
func sizeFixedS64Value(_ pointer, tagsize int) int {
	return 8 + tagsize
}
func sizeFixedS64ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toInt64()
	if v == 0 {
		return 0
	}
	return 8 + tagsize
}
func sizeFixedS64Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toInt64Ptr()
	if p == nil {
		return 0
	}
	return 8 + tagsize
}
func sizeFixedS64Slice(ptr pointer, tagsize int) int {
	s := *ptr.toInt64Slice()
	return (8 + tagsize) * len(s)
}
func sizeFixedS64PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toInt64Slice()
	if len(s) == 0 {
		return 0
	}
	return 8*len(s) + SizeVarint(uint64(8*len(s))) + tagsize
}
func sizeFloat64Value(_ pointer, tagsize int) int {
	return 8 + tagsize
}
func sizeFloat64ValueNoZero(ptr pointer, tagsize int) int {
	v := math.Float64bits(*ptr.toFloat64())
	if v == 0 {
		return 0
	}
	return 8 + tagsize
}
func sizeFloat64Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toFloat64Ptr()
	if p == nil {
		return 0
	}
	return 8 + tagsize
}
func sizeFloat64Slice(ptr pointer, tagsize int) int {
	s := *ptr.toFloat64Slice()
	return (8 + tagsize) * len(s)
}
func sizeFloat64PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toFloat64Slice()
	if len(s) == 0 {
		return 0
	}
	return 8*len(s) + SizeVarint(uint64(8*len(s))) + tagsize
}
func sizeVarint32Value(ptr pointer, tagsize int) int {
	v := *ptr.toUint32()
	return SizeVarint(uint64(v)) + tagsize
}
func sizeVarint32ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toUint32()
	if v == 0 {
		return 0
	}
	return SizeVarint(uint64(v)) + tagsize
}
func sizeVarint32Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toUint32Ptr()
	if p == nil {
		return 0
	}
	return SizeVarint(uint64(*p)) + tagsize
}
func sizeVarint32Slice(ptr pointer, tagsize int) int {
	s := *ptr.toUint32Slice()
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v)) + tagsize
	}
	return n
}
func sizeVarint32PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toUint32Slice()
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v))
	}
	return n + SizeVarint(uint64(n)) + tagsize
}
func sizeVarintS32Value(ptr pointer, tagsize int) int {
	v := *ptr.toInt32()
	return SizeVarint(uint64(v)) + tagsize
}
func sizeVarintS32ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toInt32()
	if v == 0 {
		return 0
	}
	return SizeVarint(uint64(v)) + tagsize
}
func sizeVarintS32Ptr(ptr pointer, tagsize int) int {
	p := ptr.getInt32Ptr()
	if p == nil {
		return 0
	}
	return SizeVarint(uint64(*p)) + tagsize
}
func sizeVarintS32Slice(ptr pointer, tagsize int) int {
	s := ptr.getInt32Slice()
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v)) + tagsize
	}
	return n
}
func sizeVarintS32PackedSlice(ptr pointer, tagsize int) int {
	s := ptr.getInt32Slice()
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v))
	}
	return n + SizeVarint(uint64(n)) + tagsize
}
func sizeVarint64Value(ptr pointer, tagsize int) int {
	v := *ptr.toUint64()
	return SizeVarint(v) + tagsize
}
func sizeVarint64ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toUint64()
	if v == 0 {
		return 0
	}
	return SizeVarint(v) + tagsize
}
func sizeVarint64Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toUint64Ptr()
	if p == nil {
		return 0
	}
	return SizeVarint(*p) + tagsize
}
func sizeVarint64Slice(ptr pointer, tagsize int) int {
	s := *ptr.toUint64Slice()
	n := 0
	for _, v := range s {
		n += SizeVarint(v) + tagsize
	}
	return n
}
func sizeVarint64PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toUint64Slice()
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, v := range s {
		n += SizeVarint(v)
	}
	return n + SizeVarint(uint64(n)) + tagsize
}
func sizeVarintS64Value(ptr pointer, tagsize int) int {
	v := *ptr.toInt64()
	return SizeVarint(uint64(v)) + tagsize
}
func sizeVarintS64ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toInt64()
	if v == 0 {
		return 0
	}
	return SizeVarint(uint64(v)) + tagsize
}
func sizeVarintS64Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toInt64Ptr()
	if p == nil {
		return 0
	}
	return SizeVarint(uint64(*p)) + tagsize
}
func sizeVarintS64Slice(ptr pointer, tagsize int) int {
	s := *ptr.toInt64Slice()
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v)) + tagsize
	}
	return n
}
func sizeVarintS64PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toInt64Slice()
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v))
	}
	return n + SizeVarint(uint64(n)) + tagsize
}
func sizeZigzag32Value(ptr pointer, tagsize int) int {
	v := *ptr.toInt32()
	return SizeVarint(uint64((uint32(v)<<1)^uint32((int32(v)>>31)))) + tagsize
}
func sizeZigzag32ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toInt32()
	if v == 0 {
		return 0
	}
	return SizeVarint(uint64((uint32(v)<<1)^uint32((int32(v)>>31)))) + tagsize
}
func sizeZigzag32Ptr(ptr pointer, tagsize int) int {
	p := ptr.getInt32Ptr()
	if p == nil {
		return 0
	}
	v := *p
	return SizeVarint(uint64((uint32(v)<<1)^uint32((int32(v)>>31)))) + tagsize
}
func sizeZigzag32Slice(ptr pointer, tagsize int) int {
	s := ptr.getInt32Slice()
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64((uint32(v)<<1)^uint32((int32(v)>>31)))) + tagsize
	}
	return n
}
func sizeZigzag32PackedSlice(ptr pointer, tagsize int) int {
	s := ptr.getInt32Slice()
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64((uint32(v) << 1) ^ uint32((int32(v) >> 31))))
	}
	return n + SizeVarint(uint64(n)) + tagsize
}
func sizeZigzag64Value(ptr pointer, tagsize int) int {
	v := *ptr.toInt64()
	return SizeVarint(uint64(v<<1)^uint64((int64(v)>>63))) + tagsize
}
func sizeZigzag64ValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toInt64()
	if v == 0 {
		return 0
	}
	return SizeVarint(uint64(v<<1)^uint64((int64(v)>>63))) + tagsize
}
func sizeZigzag64Ptr(ptr pointer, tagsize int) int {
	p := *ptr.toInt64Ptr()
	if p == nil {
		return 0
	}
	v := *p
	return SizeVarint(uint64(v<<1)^uint64((int64(v)>>63))) + tagsize
}
func sizeZigzag64Slice(ptr pointer, tagsize int) int {
	s := *ptr.toInt64Slice()
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v<<1)^uint64((int64(v)>>63))) + tagsize
	}
	return n
}
func sizeZigzag64PackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toInt64Slice()
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v<<1) ^ uint64((int64(v) >> 63)))
	}
	return n + SizeVarint(uint64(n)) + tagsize
}
func sizeBoolValue(_ pointer, tagsize int) int {
	return 1 + tagsize
}
func sizeBoolValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toBool()
	if !v {
		return 0
	}
	return 1 + tagsize
}


func sizeBoolPtr(ptr pointer, tagsize int) int {
	p := *ptr.toBoolPtr()
	if p == nil {
		return 0
	}
	return 1 + tagsize
}

func sizeBoolSlice(ptr pointer, tagsize int) int {
	s := *ptr.toBoolSlice()
	return (1 + tagsize) * len(s)
}

func sizeBoolPackedSlice(ptr pointer, tagsize int) int {
	s := *ptr.toBoolSlice()
	if len(s) == 0 {
		return 0
	}
	return len(s) + SizeVarint(uint64(len(s))) + tagsize
}
func sizeStringValue(ptr pointer, tagsize int) int {
	v := *ptr.toString()
	return len(v) + SizeVarint(uint64(len(v))) + tagsize
}
func sizeStringValueNoZero(ptr pointer, tagsize int) int {
	v := *ptr.toString()
	if v == "" {
		return 0
	}
	return len(v) + SizeVarint(uint64(len(v))) + tagsize
}
func sizeStringPtr(ptr pointer, tagsize int) int {
	p := *ptr.toStringPtr()
	if p == nil {
		return 0
	}
	v := *p
	return len(v) + SizeVarint(uint64(len(v))) + tagsize
}
func sizeStringSlice(ptr pointer, tagsize int) int {
	s := *ptr.toStringSlice()
	n := 0
	for _, v := range s {
		n += len(v) + SizeVarint(uint64(len(v))) + tagsize
	}
	return n
}
func sizeBytes(ptr pointer, tagsize int) int {
	v := *ptr.toBytes()
	if v == nil {
		return 0
	}
	return len(v) + SizeVarint(uint64(len(v))) + tagsize
}
func sizeBytes3(ptr pointer, tagsize int) int {
	v := *ptr.toBytes()
	if len(v) == 0 {
		return 0
	}
	return len(v) + SizeVarint(uint64(len(v))) + tagsize
}
func sizeBytesOneof(ptr pointer, tagsize int) int {
	v := *ptr.toBytes()
	return len(v) + SizeVarint(uint64(len(v))) + tagsize
}
func sizeBytesSlice(ptr pointer, tagsize int) int {
	s := *ptr.toBytesSlice()
	n := 0
	for _, v := range s {
		n += len(v) + SizeVarint(uint64(len(v))) + tagsize
	}
	return n
}

// appendFixed32 appends an encoded fixed32 to b.
func appendFixed32(b []byte, v uint32) []byte {
	b = append(b,
		byte(v),
		byte(v>>8),
		byte(v>>16),
		byte(v>>24))
	return b
}

// appendFixed64 appends an encoded fixed64 to b.
func appendFixed64(b []byte, v uint64) []byte {
	b = append(b,
		byte(v),
		byte(v>>8),
		byte(v>>16),
		byte(v>>24),
		byte(v>>32),
		byte(v>>40),
		byte(v>>48),
		byte(v>>56))
	return b
}

// appendVarint appends an encoded varint to b.
func appendVarint(b []byte, v uint64) []byte {
	// TODO: make 1-byte (maybe 2-byte) case inline-able, once we
	// have non-leaf inliner.
	switch {
	case v < 1<<7:
		b = append(b, byte(v))
	case v < 1<<14:
		b = append(b,
			byte(v&0x7f|0x80),
			byte(v>>7))
	case v < 1<<21:
		b = append(b,
			byte(v&0x7f|0x80),
			byte((v>>7)&0x7f|0x80),
			byte(v>>14))
	case v < 1<<28:
		b = append(b,
			byte(v&0x7f|0x80),
			byte((v>>7)&0x7f|0x80),
			byte((v>>14)&0x7f|0x80),
			byte(v>>21))
	case v < 1<<35:
		b = append(b,
			byte(v&0x7f|0x80),
			byte((v>>7)&0x7f|0x80),
			byte((v>>14)&0x7f|0x80),
			byte((v>>21)&0x7f|0x80),
			byte(v>>28))
	case v < 1<<42:
		b = append(b,
			byte(v&0x7f|0x80),
			byte((v>>7)&0x7f|0x80),
			byte((v>>14)&0x7f|0x80),
			byte((v>>21)&0x7f|0x80),
			byte((v>>28)&0x7f|0x80),
			byte(v>>35))
	case v < 1<<49:
		b = append(b,
			byte(v&0x7f|0x80),
			byte((v>>7)&0x7f|0x80),
			byte((v>>14)&0x7f|0x80),
			byte((v>>21)&0x7f|0x80),
			byte((v>>28)&0x7f|0x80),
			byte((v>>35)&0x7f|0x80),
			byte(v>>42))
	case v < 1<<56:
		b = append(b,
			byte(v&0x7f|0x80),
			byte((v>>7)&0x7f|0x80),
			byte((v>>14)&0x7f|0x80),
			byte((v>>21)&0x7f|0x80),
			byte((v>>28)&0x7f|0x80),
			byte((v>>35)&0x7f|0x80),
			byte((v>>42)&0x7f|0x80),
			byte(v>>49))
	case v < 1<<63:
		b = append(b,
			byte(v&0x7f|0x80),
			byte((v>>7)&0x7f|0x80),
			byte((v>>14)&0x7f|0x80),
			byte((v>>21)&0x7f|0x80),
			byte((v>>28)&0x7f|0x80),
			byte((v>>35)&0x7f|0x80),
			byte((v>>42)&0x7f|0x80),
			byte((v>>49)&0x7f|0x80),
			byte(v>>56))
	default:
		b = append(b,
			byte(v&0x7f|0x80),
			byte((v>>7)&0x7f|0x80),
			byte((v>>14)&0x7f|0x80),
			byte((v>>21)&0x7f|0x80),
			byte((v>>28)&0x7f|0x80),
			byte((v>>35)&0x7f|0x80),
			byte((v>>42)&0x7f|0x80),
			byte((v>>49)&0x7f|0x80),
			byte((v>>56)&0x7f|0x80),
			1)
	}
	return b
}

func appendFixed32Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toUint32()
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, v)
	return b, nil
}
func appendFixed32ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toUint32()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, v)
	return b, nil
}
func appendFixed32Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toUint32Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, *p)
	return b, nil
}
func appendFixed32Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toUint32Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendFixed32(b, v)
	}
	return b, nil
}
func appendFixed32PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toUint32Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	b = appendVarint(b, uint64(4*len(s)))
	for _, v := range s {
		b = appendFixed32(b, v)
	}
	return b, nil
}
func appendFixedS32Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt32()
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, uint32(v))
	return b, nil
}
func appendFixedS32ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt32()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, uint32(v))
	return b, nil
}
func appendFixedS32Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := ptr.getInt32Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, uint32(*p))
	return b, nil
}
func appendFixedS32Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := ptr.getInt32Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendFixed32(b, uint32(v))
	}
	return b, nil
}
func appendFixedS32PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := ptr.getInt32Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	b = appendVarint(b, uint64(4*len(s)))
	for _, v := range s {
		b = appendFixed32(b, uint32(v))
	}
	return b, nil
}
func appendFloat32Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := math.Float32bits(*ptr.toFloat32())
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, v)
	return b, nil
}
func appendFloat32ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := math.Float32bits(*ptr.toFloat32())
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, v)
	return b, nil
}
func appendFloat32Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toFloat32Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed32(b, math.Float32bits(*p))
	return b, nil
}
func appendFloat32Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toFloat32Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendFixed32(b, math.Float32bits(v))
	}
	return b, nil
}
func appendFloat32PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toFloat32Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	b = appendVarint(b, uint64(4*len(s)))
	for _, v := range s {
		b = appendFixed32(b, math.Float32bits(v))
	}
	return b, nil
}
func appendFixed64Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toUint64()
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, v)
	return b, nil
}
func appendFixed64ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toUint64()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, v)
	return b, nil
}
func appendFixed64Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toUint64Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, *p)
	return b, nil
}
func appendFixed64Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toUint64Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendFixed64(b, v)
	}
	return b, nil
}
func appendFixed64PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toUint64Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	b = appendVarint(b, uint64(8*len(s)))
	for _, v := range s {
		b = appendFixed64(b, v)
	}
	return b, nil
}
func appendFixedS64Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt64()
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, uint64(v))
	return b, nil
}
func appendFixedS64ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt64()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, uint64(v))
	return b, nil
}
func appendFixedS64Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toInt64Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, uint64(*p))
	return b, nil
}
func appendFixedS64Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toInt64Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendFixed64(b, uint64(v))
	}
	return b, nil
}
func appendFixedS64PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toInt64Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	b = appendVarint(b, uint64(8*len(s)))
	for _, v := range s {
		b = appendFixed64(b, uint64(v))
	}
	return b, nil
}
func appendFloat64Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := math.Float64bits(*ptr.toFloat64())
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, v)
	return b, nil
}
func appendFloat64ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := math.Float64bits(*ptr.toFloat64())
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, v)
	return b, nil
}
func appendFloat64Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toFloat64Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendFixed64(b, math.Float64bits(*p))
	return b, nil
}
func appendFloat64Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toFloat64Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendFixed64(b, math.Float64bits(v))
	}
	return b, nil
}
func appendFloat64PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toFloat64Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	b = appendVarint(b, uint64(8*len(s)))
	for _, v := range s {
		b = appendFixed64(b, math.Float64bits(v))
	}
	return b, nil
}
func appendVarint32Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toUint32()
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(v))
	return b, nil
}
func appendVarint32ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toUint32()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(v))
	return b, nil
}
func appendVarint32Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toUint32Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(*p))
	return b, nil
}
func appendVarint32Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toUint32Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendVarint(b, uint64(v))
	}
	return b, nil
}
func appendVarint32PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toUint32Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	// compute size
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v))
	}
	b = appendVarint(b, uint64(n))
	for _, v := range s {
		b = appendVarint(b, uint64(v))
	}
	return b, nil
}
func appendVarintS32Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt32()
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(v))
	return b, nil
}
func appendVarintS32ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt32()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(v))
	return b, nil
}
func appendVarintS32Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := ptr.getInt32Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(*p))
	return b, nil
}
func appendVarintS32Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := ptr.getInt32Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendVarint(b, uint64(v))
	}
	return b, nil
}
func appendVarintS32PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := ptr.getInt32Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	// compute size
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v))
	}
	b = appendVarint(b, uint64(n))
	for _, v := range s {
		b = appendVarint(b, uint64(v))
	}
	return b, nil
}
func appendVarint64Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toUint64()
	b = appendVarint(b, wiretag)
	b = appendVarint(b, v)
	return b, nil
}
func appendVarint64ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toUint64()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, v)
	return b, nil
}
func appendVarint64Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toUint64Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, *p)
	return b, nil
}
func appendVarint64Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toUint64Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendVarint(b, v)
	}
	return b, nil
}
func appendVarint64PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toUint64Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	// compute size
	n := 0
	for _, v := range s {
		n += SizeVarint(v)
	}
	b = appendVarint(b, uint64(n))
	for _, v := range s {
		b = appendVarint(b, v)
	}
	return b, nil
}
func appendVarintS64Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt64()
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(v))
	return b, nil
}
func appendVarintS64ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt64()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(v))
	return b, nil
}
func appendVarintS64Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toInt64Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(*p))
	return b, nil
}
func appendVarintS64Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toInt64Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendVarint(b, uint64(v))
	}
	return b, nil
}
func appendVarintS64PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toInt64Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	// compute size
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v))
	}
	b = appendVarint(b, uint64(n))
	for _, v := range s {
		b = appendVarint(b, uint64(v))
	}
	return b, nil
}
func appendZigzag32Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt32()
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64((uint32(v)<<1)^uint32((int32(v)>>31))))
	return b, nil
}
func appendZigzag32ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt32()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64((uint32(v)<<1)^uint32((int32(v)>>31))))
	return b, nil
}
func appendZigzag32Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := ptr.getInt32Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	v := *p
	b = appendVarint(b, uint64((uint32(v)<<1)^uint32((int32(v)>>31))))
	return b, nil
}
func appendZigzag32Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := ptr.getInt32Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendVarint(b, uint64((uint32(v)<<1)^uint32((int32(v)>>31))))
	}
	return b, nil
}
func appendZigzag32PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := ptr.getInt32Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	// compute size
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64((uint32(v) << 1) ^ uint32((int32(v) >> 31))))
	}
	b = appendVarint(b, uint64(n))
	for _, v := range s {
		b = appendVarint(b, uint64((uint32(v)<<1)^uint32((int32(v)>>31))))
	}
	return b, nil
}
func appendZigzag64Value(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt64()
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(v<<1)^uint64((int64(v)>>63)))
	return b, nil
}
func appendZigzag64ValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toInt64()
	if v == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(v<<1)^uint64((int64(v)>>63)))
	return b, nil
}
func appendZigzag64Ptr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toInt64Ptr()
	if p == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	v := *p
	b = appendVarint(b, uint64(v<<1)^uint64((int64(v)>>63)))
	return b, nil
}
func appendZigzag64Slice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toInt64Slice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendVarint(b, uint64(v<<1)^uint64((int64(v)>>63)))
	}
	return b, nil
}
func appendZigzag64PackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toInt64Slice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	// compute size
	n := 0
	for _, v := range s {
		n += SizeVarint(uint64(v<<1) ^ uint64((int64(v) >> 63)))
	}
	b = appendVarint(b, uint64(n))
	for _, v := range s {
		b = appendVarint(b, uint64(v<<1)^uint64((int64(v)>>63)))
	}
	return b, nil
}
func appendBoolValue(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toBool()
	b = appendVarint(b, wiretag)
	if v {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return b, nil
}
func appendBoolValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toBool()
	if !v {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = append(b, 1)
	return b, nil
}

func appendBoolPtr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {

	p := *ptr.toBoolPtr()
	if p == nil {
		return b, nil
	}

	b = appendVarint(b, wiretag)
	if *p {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}

	return b, nil
}
func appendBoolSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toBoolSlice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		if v {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	return b, nil
}
func appendBoolPackedSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toBoolSlice()
	if len(s) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag&^7|WireBytes)
	b = appendVarint(b, uint64(len(s)))
	for _, v := range s {
		if v {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	return b, nil
}

// wiretag | data | wiretag | data | ... | data |
func appendStringValue(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toString()
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	return b, nil
}

func appendStringValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toString()
	if v == "" {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	return b, nil
}
func appendStringPtr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	p := *ptr.toStringPtr()
	if p == nil {
		return b, nil
	}
	v := *p
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	return b, nil
}
func appendStringSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toStringSlice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendVarint(b, uint64(len(v)))
		b = append(b, v...)
	}
	return b, nil
}
func appendUTF8StringValue(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	var invalidUTF8 bool
	v := *ptr.toString()
	if !utf8.ValidString(v) {
		invalidUTF8 = true
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	if invalidUTF8 {
		return b, errInvalidUTF8
	}
	return b, nil
}
func appendUTF8StringValueNoZero(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	var invalidUTF8 bool
	v := *ptr.toString()
	if v == "" {
		return b, nil
	}
	if !utf8.ValidString(v) {
		invalidUTF8 = true
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	if invalidUTF8 {
		return b, errInvalidUTF8
	}
	return b, nil
}
func appendUTF8StringPtr(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	var invalidUTF8 bool
	p := *ptr.toStringPtr()
	if p == nil {
		return b, nil
	}
	v := *p
	if !utf8.ValidString(v) {
		invalidUTF8 = true
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	if invalidUTF8 {
		return b, errInvalidUTF8
	}
	return b, nil
}
func appendUTF8StringSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	var invalidUTF8 bool
	s := *ptr.toStringSlice()
	for _, v := range s {
		if !utf8.ValidString(v) {
			invalidUTF8 = true
		}
		b = appendVarint(b, wiretag)
		b = appendVarint(b, uint64(len(v)))
		b = append(b, v...)
	}
	if invalidUTF8 {
		return b, errInvalidUTF8
	}
	return b, nil
}
func appendBytes(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toBytes()
	if v == nil {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	return b, nil
}
func appendBytes3(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toBytes()
	if len(v) == 0 {
		return b, nil
	}
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	return b, nil
}
func appendBytesOneof(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	v := *ptr.toBytes()
	b = appendVarint(b, wiretag)
	b = appendVarint(b, uint64(len(v)))
	b = append(b, v...)
	return b, nil
}
func appendBytesSlice(b []byte, ptr pointer, wiretag uint64, _ bool) ([]byte, error) {
	s := *ptr.toBytesSlice()
	for _, v := range s {
		b = appendVarint(b, wiretag)
		b = appendVarint(b, uint64(len(v)))
		b = append(b, v...)
	}
	return b, nil
}

// makeGroupMarshaler returns the sizer and marshaler for a group.
// u is the marshal info of the underlying message.
func makeGroupMarshaler(u *marshalInfo) (sizer, marshaler) {
	return func(ptr pointer, tagsize int) int {
			p := ptr.getPointer()
			if p.isNil() {
				return 0
			}
			return u.size(p) + 2*tagsize
		},
		func(b []byte, ptr pointer, wiretag uint64, deterministic bool) ([]byte, error) {
			p := ptr.getPointer()
			if p.isNil() {
				return b, nil
			}
			var err error
			b = appendVarint(b, wiretag) // start group
			b, err = u.marshal(b, p, deterministic)
			b = appendVarint(b, wiretag+(WireEndGroup-WireStartGroup)) // end group
			return b, err
		}
}

// makeGroupSliceMarshaler returns the sizer and marshaler for a group slice.
// u is the marshal info of the underlying message.
func makeGroupSliceMarshaler(u *marshalInfo) (sizer, marshaler) {
	return func(ptr pointer, tagsize int) int {
			s := ptr.getPointerSlice()
			n := 0
			for _, v := range s {
				if v.isNil() {
					continue
				}
				n += u.size(v) + 2*tagsize
			}
			return n
		},
		func(b []byte, ptr pointer, wiretag uint64, deterministic bool) ([]byte, error) {
			s := ptr.getPointerSlice()
			var err error
			var nerr nonFatal
			for _, v := range s {
				if v.isNil() {
					return b, errRepeatedHasNil
				}
				b = appendVarint(b, wiretag) // start group
				b, err = u.marshal(b, v, deterministic)
				b = appendVarint(b, wiretag+(WireEndGroup-WireStartGroup)) // end group
				if !nerr.Merge(err) {
					if err == ErrNil {
						err = errRepeatedHasNil
					}
					return b, err
				}
			}
			return b, nerr.E
		}
}

// makeMessageMarshaler returns the sizer and marshaler for a message field.
// u is the marshal info of the message.
func makeMessageMarshaler(u *marshalInfo) (sizer, marshaler) {
	return func(ptr pointer, tagsize int) int {
			p := ptr.getPointer()
			if p.isNil() {
				return 0
			}
			siz := u.size(p)
			return siz + SizeVarint(uint64(siz)) + tagsize
		},
		func(b []byte, ptr pointer, wiretag uint64, deterministic bool) ([]byte, error) {
			p := ptr.getPointer()
			if p.isNil() {
				return b, nil
			}
			b = appendVarint(b, wiretag)
			siz := u.cachedsize(p)
			b = appendVarint(b, uint64(siz))
			return u.marshal(b, p, deterministic)
		}
}

// makeMessageSliceMarshaler returns the sizer and marshaler for a message slice.
// u is the marshal info of the message.
func makeMessageSliceMarshaler(u *marshalInfo) (sizer, marshaler) {
	return func(ptr pointer, tagsize int) int {
			s := ptr.getPointerSlice()
			n := 0
			for _, v := range s {
				if v.isNil() {
					continue
				}
				siz := u.size(v)
				n += siz + SizeVarint(uint64(siz)) + tagsize
			}
			return n
		},
		func(b []byte, ptr pointer, wiretag uint64, deterministic bool) ([]byte, error) {
			s := ptr.getPointerSlice()
			var err error
			var nerr nonFatal
			for _, v := range s {
				if v.isNil() {
					return b, errRepeatedHasNil
				}
				b = appendVarint(b, wiretag)
				siz := u.cachedsize(v)
				b = appendVarint(b, uint64(siz))
				b, err = u.marshal(b, v, deterministic)

				if !nerr.Merge(err) {
					if err == ErrNil {
						err = errRepeatedHasNil
					}
					return b, err
				}
			}
			return b, nerr.E
		}
}

// makeMapMarshaler returns the sizer and marshaler for a map field.
// f is the pointer to the reflect data structure of the field.
func makeMapMarshaler(f *reflect.StructField) (sizer, marshaler) {
	// figure out key and value type
	t := f.Type
	keyType := t.Key()
	valType := t.Elem()
	keyTags := strings.Split(f.Tag.Get("protobuf_key"), ",")
	valTags := strings.Split(f.Tag.Get("protobuf_val"), ",")
	keySizer, keyMarshaler := typeMarshaler(keyType, keyTags, false, false) // don't omit zero value in map
	valSizer, valMarshaler := typeMarshaler(valType, valTags, false, false) // don't omit zero value in map
	keyWireTag := 1<<3 | wiretype(keyTags[0])
	valWireTag := 2<<3 | wiretype(valTags[0])

	// We create an interface to get the addresses of the map key and value.
	// If value is pointer-typed, the interface is a direct interface, the
	// idata itself is the value. Otherwise, the idata is the pointer to the
	// value.
	// Key cannot be pointer-typed.
	valIsPtr := valType.Kind() == reflect.Ptr

	// If value is a message with nested maps, calling
	// valSizer in marshal may be quadratic. We should use
	// cached version in marshal (but not in size).
	// If value is not message type, we don't have size cache,
	// but it cannot be nested either. Just use valSizer.
	valCachedSizer := valSizer
	if valIsPtr && valType.Elem().Kind() == reflect.Struct {
		u := getMarshalInfo(valType.Elem())
		valCachedSizer = func(ptr pointer, tagsize int) int {
			// Same as message sizer, but use cache.
			p := ptr.getPointer()
			if p.isNil() {
				return 0
			}
			siz := u.cachedsize(p)
			return siz + SizeVarint(uint64(siz)) + tagsize
		}
	}
	return func(ptr pointer, tagsize int) int {
			m := ptr.asPointerTo(t).Elem() // the map
			n := 0
			for _, k := range m.MapKeys() {
				ki := k.Interface()
				vi := m.MapIndex(k).Interface()
				kaddr := toAddrPointer(&ki, false, false)      // pointer to key
				vaddr := toAddrPointer(&vi, valIsPtr, false)   // pointer to value
				siz := keySizer(kaddr, 1) + valSizer(vaddr, 1) // tag of key = 1 (size=1), tag of val = 2 (size=1)
				n += siz + SizeVarint(uint64(siz)) + tagsize
			}
			return n
		},
		func(b []byte, ptr pointer, tag uint64, deterministic bool) ([]byte, error) {
			m := ptr.asPointerTo(t).Elem() // the map
			var err error
			keys := m.MapKeys()
			if len(keys) > 1 && deterministic {
				sort.Sort(mapKeys(keys))
			}

			var nerr nonFatal
			for _, k := range keys {
				ki := k.Interface()
				vi := m.MapIndex(k).Interface()
				kaddr := toAddrPointer(&ki, false, false)    // pointer to key
				vaddr := toAddrPointer(&vi, valIsPtr, false) // pointer to value
				b = appendVarint(b, tag)
				siz := keySizer(kaddr, 1) + valCachedSizer(vaddr, 1) // tag of key = 1 (size=1), tag of val = 2 (size=1)
				b = appendVarint(b, uint64(siz))
				b, err = keyMarshaler(b, kaddr, keyWireTag, deterministic)
				if !nerr.Merge(err) {
					return b, err
				}
				b, err = valMarshaler(b, vaddr, valWireTag, deterministic)
				if err != ErrNil && !nerr.Merge(err) { // allow nil value in map
					return b, err
				}
			}
			return b, nerr.E
		}
}

// makeOneOfMarshaler returns the sizer and marshaler for a oneof field.
// fi is the marshal info of the field.
// f is the pointer to the reflect data structure of the field.
func makeOneOfMarshaler(fi *marshalFieldInfo, f *reflect.StructField) (sizer, marshaler) {
	// Oneof field is an interface. We need to get the actual data type on the fly.
	t := f.Type
	return func(ptr pointer, _ int) int {
			p := ptr.getInterfacePointer()
			if p.isNil() {
				return 0
			}
			v := ptr.asPointerTo(t).Elem().Elem().Elem() // *interface -> interface -> *struct -> struct
			telem := v.Type()
			e := fi.oneofElems[telem]
			return e.sizer(p, e.tagsize)
		},
		func(b []byte, ptr pointer, _ uint64, deterministic bool) ([]byte, error) {
			p := ptr.getInterfacePointer()
			if p.isNil() {
				return b, nil
			}
			v := ptr.asPointerTo(t).Elem().Elem().Elem() // *interface -> interface -> *struct -> struct
			telem := v.Type()
			if telem.Field(0).Type.Kind() == reflect.Ptr && p.getPointer().isNil() {
				return b, errOneofHasNil
			}
			e := fi.oneofElems[telem]
			return e.marshaler(b, p, e.wiretag, deterministic)
		}
}

// sizeExtensions computes the size of encoded data for a XXX_InternalExtensions field.
func (u *marshalInfo) sizeExtensions(ext *XXX_InternalExtensions) int {
	m, mu := ext.extensionsRead()
	if m == nil {
		return 0
	}
	mu.Lock()

	n := 0
	for _, e := range m {
		if e.value == nil || e.desc == nil {
			// Extension is only in its encoded form.
			n += len(e.enc)
			continue
		}

		// We don't skip extensions that have an encoded form set,
		// because the extension value may have been mutated after
		// the last time this function was called.
		ei := u.getExtElemInfo(e.desc)
		v := e.value
		p := toAddrPointer(&v, ei.isptr, ei.deref)
		n += ei.sizer(p, ei.tagsize)
	}
	mu.Unlock()
	return n
}

// appendExtensions marshals a XXX_InternalExtensions field to the end of byte slice b.
func (u *marshalInfo) appendExtensions(b []byte, ext *XXX_InternalExtensions, deterministic bool) ([]byte, error) {
	m, mu := ext.extensionsRead()
	if m == nil {
		return b, nil
	}
	mu.Lock()
	defer mu.Unlock()

	var err error
	var nerr nonFatal

	// Fast-path for common cases: zero or one extensions.
	// Don't bother sorting the keys.
	if len(m) <= 1 {
		for _, e := range m {
			if e.value == nil || e.desc == nil {
				// Extension is only in its encoded form.
				b = append(b, e.enc...)
				continue
			}

			// We don't skip extensions that have an encoded form set,
			// because the extension value may have been mutated after
			// the last time this function was called.

			ei := u.getExtElemInfo(e.desc)
			v := e.value
			p := toAddrPointer(&v, ei.isptr, ei.deref)
			b, err = ei.marshaler(b, p, ei.wiretag, deterministic)
			if !nerr.Merge(err) {
				return b, err
			}
		}
		return b, nerr.E
	}

	// Sort the keys to provide a deterministic encoding.
	// Not sure this is required, but the old code does it.
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	for _, k := range keys {
		e := m[int32(k)]
		if e.value == nil || e.desc == nil {
			// Extension is only in its encoded form.
			b = append(b, e.enc...)
			continue
		}

		// We don't skip extensions that have an encoded form set,
		// because the extension value may have been mutated after
		// the last time this function was called.

		ei := u.getExtElemInfo(e.desc)
		v := e.value
		p := toAddrPointer(&v, ei.isptr, ei.deref)
		b, err = ei.marshaler(b, p, ei.wiretag, deterministic)
		if !nerr.Merge(err) {
			return b, err
		}
	}
	return b, nerr.E
}

// message set format is:
//   message MessageSet {
//     repeated group Item = 1 {
//       required int32 type_id = 2;
//       required string message = 3;
//     };
//   }

// sizeMessageSet computes the size of encoded data for a XXX_InternalExtensions field
// in message set format (above).
func (u *marshalInfo) sizeMessageSet(ext *XXX_InternalExtensions) int {
	m, mu := ext.extensionsRead()
	if m == nil {
		return 0
	}
	mu.Lock()

	n := 0
	for id, e := range m {
		n += 2                          // start group, end group. tag = 1 (size=1)
		n += SizeVarint(uint64(id)) + 1 // type_id, tag = 2 (size=1)

		if e.value == nil || e.desc == nil {
			// Extension is only in its encoded form.
			msgWithLen := skipVarint(e.enc) // skip old tag, but leave the length varint
			siz := len(msgWithLen)
			n += siz + 1 // message, tag = 3 (size=1)
			continue
		}

		// We don't skip extensions that have an encoded form set,
		// because the extension value may have been mutated after
		// the last time this function was called.

		ei := u.getExtElemInfo(e.desc)
		v := e.value
		p := toAddrPointer(&v, ei.isptr, ei.deref)
		n += ei.sizer(p, 1) // message, tag = 3 (size=1)
	}
	mu.Unlock()
	return n
}

// appendMessageSet marshals a XXX_InternalExtensions field in message set format (above)
// to the end of byte slice b.
func (u *marshalInfo) appendMessageSet(b []byte, ext *XXX_InternalExtensions, deterministic bool) ([]byte, error) {
	m, mu := ext.extensionsRead()
	if m == nil {
		return b, nil
	}
	mu.Lock()
	defer mu.Unlock()

	var err error
	var nerr nonFatal

	// Fast-path for common cases: zero or one extensions.
	// Don't bother sorting the keys.
	if len(m) <= 1 {
		for id, e := range m {
			b = append(b, 1<<3|WireStartGroup)
			b = append(b, 2<<3|WireVarint)
			b = appendVarint(b, uint64(id))

			if e.value == nil || e.desc == nil {
				// Extension is only in its encoded form.
				msgWithLen := skipVarint(e.enc) // skip old tag, but leave the length varint
				b = append(b, 3<<3|WireBytes)
				b = append(b, msgWithLen...)
				b = append(b, 1<<3|WireEndGroup)
				continue
			}

			// We don't skip extensions that have an encoded form set,
			// because the extension value may have been mutated after
			// the last time this function was called.

			ei := u.getExtElemInfo(e.desc)
			v := e.value
			p := toAddrPointer(&v, ei.isptr, ei.deref)
			b, err = ei.marshaler(b, p, 3<<3|WireBytes, deterministic)
			if !nerr.Merge(err) {
				return b, err
			}
			b = append(b, 1<<3|WireEndGroup)
		}
		return b, nerr.E
	}

	// Sort the keys to provide a deterministic encoding.
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	for _, id := range keys {
		e := m[int32(id)]
		b = append(b, 1<<3|WireStartGroup)
		b = append(b, 2<<3|WireVarint)
		b = appendVarint(b, uint64(id))

		if e.value == nil || e.desc == nil {
			// Extension is only in its encoded form.
			msgWithLen := skipVarint(e.enc) // skip old tag, but leave the length varint
			b = append(b, 3<<3|WireBytes)
			b = append(b, msgWithLen...)
			b = append(b, 1<<3|WireEndGroup)
			continue
		}

		// We don't skip extensions that have an encoded form set,
		// because the extension value may have been mutated after
		// the last time this function was called.

		ei := u.getExtElemInfo(e.desc)
		v := e.value
		p := toAddrPointer(&v, ei.isptr, ei.deref)
		b, err = ei.marshaler(b, p, 3<<3|WireBytes, deterministic)
		b = append(b, 1<<3|WireEndGroup)
		if !nerr.Merge(err) {
			return b, err
		}
	}
	return b, nerr.E
}

// sizeV1Extensions computes the size of encoded data for a V1-API extension field.
func (u *marshalInfo) sizeV1Extensions(m map[int32]Extension) int {
	if m == nil {
		return 0
	}

	n := 0
	for _, e := range m {
		if e.value == nil || e.desc == nil {
			// Extension is only in its encoded form.
			n += len(e.enc)
			continue
		}

		// We don't skip extensions that have an encoded form set,
		// because the extension value may have been mutated after
		// the last time this function was called.

		ei := u.getExtElemInfo(e.desc)
		v := e.value
		p := toAddrPointer(&v, ei.isptr, ei.deref)
		n += ei.sizer(p, ei.tagsize)
	}
	return n
}

// appendV1Extensions marshals a V1-API extension field to the end of byte slice b.
func (u *marshalInfo) appendV1Extensions(b []byte, m map[int32]Extension, deterministic bool) ([]byte, error) {
	if m == nil {
		return b, nil
	}

	// Sort the keys to provide a deterministic encoding.
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	var err error
	var nerr nonFatal
	for _, k := range keys {
		e := m[int32(k)]
		if e.value == nil || e.desc == nil {
			// Extension is only in its encoded form.
			b = append(b, e.enc...)
			continue
		}

		// We don't skip extensions that have an encoded form set,
		// because the extension value may have been mutated after
		// the last time this function was called.

		ei := u.getExtElemInfo(e.desc)
		v := e.value
		p := toAddrPointer(&v, ei.isptr, ei.deref)
		b, err = ei.marshaler(b, p, ei.wiretag, deterministic)
		if !nerr.Merge(err) {
			return b, err
		}
	}
	return b, nerr.E
}

// newMarshaler is the interface representing objects that can marshal themselves.
//
// This exists to support protoc-gen-go generated messages.
// The proto package will stop type-asserting to this interface in the future.
//
// DO NOT DEPEND ON THIS.
type newMarshaler interface {
	XXX_Size() int
	XXX_Marshal(b []byte, deterministic bool) ([]byte, error)
}

// Size returns the encoded size of a protocol buffer message.
// This is the main entry point.
func Size(pb Message) int {
	if m, ok := pb.(newMarshaler); ok {
		return m.XXX_Size()
	}
	if m, ok := pb.(Marshaler); ok {
		// If the message can marshal itself, let it do it, for compatibility.
		// NOTE: This is not efficient.
		b, _ := m.Marshal()
		return len(b)
	}
	// in case somehow we didn't generate the wrapper
	if pb == nil {
		return 0
	}
	var info InternalMessageInfo
	return info.Size(pb)
}

// Marshal takes a protocol buffer message
// and encodes it into the wire format, returning the data.
// This is the main entry point.
func Marshal(pb Message) ([]byte, error) {
	if m, ok := pb.(newMarshaler); ok {
		siz := m.XXX_Size()
		b := make([]byte, 0, siz)
		return m.XXX_Marshal(b, false)
	}
	if m, ok := pb.(Marshaler); ok {
		// If the message can marshal itself, let it do it, for compatibility.
		// NOTE: This is not efficient.
		return m.Marshal()
	}
	// in case somehow we didn't generate the wrapper
	if pb == nil {
		return nil, ErrNil
	}
	var info InternalMessageInfo
	siz := info.Size(pb)
	b := make([]byte, 0, siz)
	return info.Marshal(b, pb, false)
}

// Marshal takes a protocol buffer message
// and encodes it into the wire format, writing the result to the
// Buffer.
// This is an alternative entry point. It is not necessary to use
// a Buffer for most applications.
func (p *Buffer) Marshal(pb Message) error {

	var err error

	if m, ok := pb.(newMarshaler); ok {
		siz := m.XXX_Size()
		p.grow(siz) // make sure buf has enough capacity
		p.buf, err = m.XXX_Marshal(p.buf, p.deterministic)
		return err
	}

	if m, ok := pb.(Marshaler); ok {
		// If the message can marshal itself, let it do it, for compatibility.
		// NOTE: This is not efficient.
		b, err := m.Marshal()
		p.buf = append(p.buf, b...)
		return err
	}

	// in case somehow we didn't generate the wrapper
	if pb == nil {
		return ErrNil
	}

	var info InternalMessageInfo

	// 计算消息 size
	siz := info.Size(pb)

	// 确保至少能够容纳 siz 个字节
	p.grow(siz) // make sure buf has enough capacity

	// 执行 Marshal ，将 pb 序列化成二进制保存到 p.bud 上
	p.buf, err = info.Marshal(p.buf, pb, p.deterministic)

	return err
}

// grow grows the buffer's capacity, if necessary, to guarantee space for another n bytes.
// After grow(n), at least n bytes can be written to the buffer without another allocation.
func (p *Buffer) grow(n int) {
	// 是否充足
	need := len(p.buf) + n
	if need <= cap(p.buf) {
		return
	}

	// 扩容 2 倍
	newCap := len(p.buf) * 2
	if newCap < need {
		newCap = need
	}

	// 扩容 + 拷贝
	p.buf = append(make([]byte, 0, newCap), p.buf...)
}
