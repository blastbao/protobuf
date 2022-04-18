// Go support for Protocol Buffers - Google's data interchange format
//
// Copyright 2010 The Go Authors.  All rights reserved.
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

/*
 * Routines for encoding data into the wire format for protocol buffers.
 */

import (
	"errors"
	"reflect"
)

var (
	// errRepeatedHasNil is the error returned if Marshal is called with
	// a struct with a repeated field containing a nil element.
	errRepeatedHasNil = errors.New("proto: repeated field has nil element")

	// errOneofHasNil is the error returned if Marshal is called with
	// a struct with a oneof field containing a nil element.
	errOneofHasNil = errors.New("proto: oneof field has nil value")

	// ErrNil is the error returned if Marshal is called with nil.
	ErrNil = errors.New("proto: Marshal called with nil")

	// ErrTooLarge is the error returned if Marshal is called with a
	// message that encodes to >2GB.
	ErrTooLarge = errors.New("proto: message encodes to over 2 GB")
)

// Varint 是一种紧凑的表示数字的方法。它用一个或多个字节来表示一个数字，值越小的数字使用越少的字节数，这能减少用来表示数字的字节数。
//
// 比如对于 int32 类型的数字，一般需要 4 个 byte 来表示。但是采用 Varint，对于很小的 int32 类型的数字，则可以用 1 个 byte 来表示。
// 当然凡事都有好的也有不好的一面，采用 Varint 表示法，大的数字则需要 5 个 byte 来表示。
// 从统计的角度来说，一般不会所有的消息中的数字都是大数，因此大多数情况下，采用 Varint 后，可以用更少的字节数来表示数字信息。
//
// 举例来说，300 如果用 int32 表示，需要 4 个字节，现在用 Varint 表示，只需要 2 个字节了。缩小了一半！
//
// Varint 中的每个字节（最后一个字节除外）都设置了最高有效位（msb），这一位表示还会有更多字节出现。
// 每个字节的低 7 位用于以 7 位组的形式存储数字的二进制补码表示，最低有效组首位。
//
// 如果用不到 1 个字节，那么最高有效位设为 0 ，如下面这个例子，1 用一个字节就可以表示，所以 msb 为 0.
//
// [0]000 0001
//
// 如果需要多个字节表示，msb 就应该设置为 1 。例如 300，如果用 Varint 表示的话：
//
// [1]010 1100 [0]000 0010
//
// 如果按照正常的二进制计算的话，这个表示的是 88068(65536 + 16384 + 4096 + 2048 + 4)，那 Varint 是怎么编码的呢？
//
//
// Varint 的解码算法应该是这样的：（实际就是编码的逆过程）
//	如果是多个字节，先去掉每个字节的 msb（通过逻辑或运算），每个字节只留下 7 位。
//	按字节逆序翻转， varint 最多是 5 个字节，排序是 1-2-3-4-5，逆序之后就是 5-4-3-2-1，字节内部的二进制位的顺序不变，变的是字节的相对位置。
//


// varint 是一种可变长编码，使用1个或多个字节对整数进行编码，可编码任意大的整数，小整数占用的字节少，
// 大整数占用的字节多，如果小整数更频繁出现，则通过 varint 可实现压缩存储。
//
//
// varint 中每个字节的最高位 bit 称之为 most significant bit (MSB)，
// 如果该 bit 为 0 意味着这个字节为表示当前整数的最后一个字节，如果为 1 则表示后面还有至少 1 个字节，
// 可见，varint 的终止位置其实是自解释的。
//
//
// 在 Protobuf 中，tag 和 length 都是使用 varint 编码的。
// length 和 tag 中的 field_number 都是正整数 int32 ，这里提一下 tag ，它的低 3 位 bit 为 wire type ，
// 如果只用 1 个字节表示的话，最高位 bit 为 0 ，则留给 field_number 只有 4 个 bit 位，数值 1 到 15 ，
// 如果 field_number 大于等于 16 ，就需要用 2 个字节，所以对于频繁使用的 field 其 field_number 应设置为 1 到 15 。
//

// Varint 的编码，以 300 举例：
// 由于 300 超过了 7 位（Varint 一个字节只有 7 位能用来表示数字，最高位 msb 用来表示后面是否有更多字节），所以 300 需要用 2 个字节来表示。
// 即：
// 	1010 1100 0000 0010
//
// 怎么解释呢？
//
// 去掉各个字节的首位：
//  1010 1100 0000 0010
// → 010 1100  000 0010
//
// 把两个 7bit 的组翻转过来, 记得 varints 保存数字是 least significant group first (汗)：
//
//   000 0010  010 1100
//
// 拼接：
//  000 0010 + 010 1100
// → 100101100
//
// 进而得到最后的值:
// → 256 + 32 + 8 + 4 = 300



// The fundamental encoders that put bytes on the wire.
// Those that take integer types all accept uint64 and are
// therefore of type valueEncoder.

const maxVarintBytes = 10 // maximum length of a varint


// EncodeVarint returns the varint encoding of x.
// This is the format for the int32, int64, uint32, uint64, bool, and enum protocol buffer types.
// Not used by the package itself, but helpful to clients wishing to use the same encoding.
//
//
// [编码过程]
//  我们从头到尾来推断一下 300 这个数字的编码过程:
//
//	整型 300 的标准 32 位(4字节)二进制表示为 "00000000 00000000 00000001 00101100"
//	从后向前每次按 7 bit 分隔为 "0000010 0101100" , 剩下全是 0 的忽略
//	翻转过来得到 "0101100 0000010"
//	为每个 7bit 增加msb, 前面 7bit 之前加 1 表示后面还有数据并凑成 8bit 为一个 byte , 最后一个 msb 设置为 0 , 这样得到 "10101100 00000010" 。
//
func EncodeVarint(x uint64) []byte {
	var buf [maxVarintBytes]byte
	var n int
	// 将 x 分拆为标准二进制的 n 个 bytes ，逆序保存到 buf 中
	for n = 0; x > 127; n++ {
		// 非最低位 byte 的首个 bit 置为 1
		buf[n] = 0x80 | uint8(x&0x7F)
		x >>= 7
	}
	// 最低的 byte 的首个 bit 置 0
	buf[n] = uint8(x)
	n++
	// 返回
	return buf[0:n]
}

// EncodeVarint writes a varint-encoded integer to the Buffer.
// This is the format for the int32, int64, uint32, uint64, bool, and enum protocol buffer types.
func (p *Buffer) EncodeVarint(x uint64) error {
	for x >= 1<<7 {
		p.buf = append(p.buf, uint8(x&0x7f|0x80))
		x >>= 7
	}
	p.buf = append(p.buf, uint8(x))
	return nil
}

// SizeVarint returns the varint encoding size of an integer.
func SizeVarint(x uint64) int {
	switch {
	case x < 1<<7:
		return 1
	case x < 1<<14:
		return 2
	case x < 1<<21:
		return 3
	case x < 1<<28:
		return 4
	case x < 1<<35:
		return 5
	case x < 1<<42:
		return 6
	case x < 1<<49:
		return 7
	case x < 1<<56:
		return 8
	case x < 1<<63:
		return 9
	}
	return 10
}

// EncodeFixed64 writes a 64-bit integer to the Buffer.
// This is the format for the fixed64, sfixed64, and double protocol buffer types.
//
// 对于 Fixed64 的处理，仅仅只是位移操作，并没有做什么压缩操作。
func (p *Buffer) EncodeFixed64(x uint64) error {
	p.buf = append(p.buf, uint8(x), uint8(x>>8), uint8(x>>16), uint8(x>>24), uint8(x>>32), uint8(x>>40), uint8(x>>48), uint8(x>>56))
	return nil
}

// EncodeFixed32 writes a 32-bit integer to the Buffer.
// This is the format for the fixed32, sfixed32, and float protocol buffer types.
//
// 对于 Fixed32 的处理，仅仅只是位移操作，并没有做什么压缩操作。
func (p *Buffer) EncodeFixed32(x uint64) error {
	p.buf = append(p.buf, uint8(x), uint8(x>>8), uint8(x>>16), uint8(x>>24))
	return nil
}

// EncodeZigzag64 writes a zigzag-encoded 64-bit integer to the Buffer.
// This is the format used for the sint64 protocol buffer type.
//
// 针对有符号的 int64 ，采取的是先 Zigzag，然后在 Varint 的处理方式。
func (p *Buffer) EncodeZigzag64(x uint64) error {
	// use signed number to get arithmetic right shift.
	return p.EncodeVarint(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}

// EncodeZigzag32 writes a zigzag-encoded 32-bit integer to the Buffer.
// This is the format used for the sint32 protocol buffer type.
//
// 针对有符号的 int32 ，采取的是先 Zigzag，然后在 Varint 的处理方式。
//
//
// 所有和类型 0 关联的 protocol buffer 类型被编码为 varints .
// 但是, 当编码负数的时候, 在有符号整型(sint32和sint64) 和 "标准" 整型类型(int32和int64)之间有一个重要的差别.
// 如果用 int32 或者 int64 作为一个负数的类型, 所得结果的 varint 总是 10 个字节长度 - 它被当成一个非常巨大的无符号整型处理.
// 如果使用有符号类型, 所得结果的 varint 使用更有效率的 ZigZag 编码.
//
// [重要]
// ZigZag 编码将有符号整型映射到无符号整型, 所有绝对值小的值(比如 -1 )数字会得到一个小的 varint 编码值.
// 实现的方式是 "zig-zags" , 直接把最高位(符号位)的放到最后面，这样编码后数值会在正数和负数整型之间来回摇摆,
// 正数为偶数（原来的两倍），负数为奇数（绝对值的两倍 -1 ） 例如： -1 被编码为 1 , 1 被编码为 2 , -2 被编码为 3 ,
// 由此类推, 在下面的表格中可以看到:
//
// 原始有符号整型		编码结果
//	0				0
//	-1				1
//	1				2
//	2				3
//	2147483647		4294967294
//	-2147483648		4294967295
//
//
// 换句话说, 对于 sint32 , 每个值 n 被编码为:
// 		(n << 1) ^ (n >> 31)
// 或者64位版本:
//		(n << 1) ^ (n >> 63)
//
// 注意第二个移动 (n >> 31) 部分 - 是一个算数 shift(arithmetic shift) .
// 因此,移动返回的结果要么是 0 (如果 n 是正数) 要么是 1 (如果 n 是负数).
//
// 当 sint32 或者 sint64 被解析时, 它的值被解码回原始值, 有符号的版本.
//
//
//
// 看 Go 源码的实现，先将数字转为 uint64 ，负数在计算机会以补码的形式存在，
// 例如 -5 的补码为：
//	1111111111111111111111111111111111111111111111111111111111111011
// 然后左移一位得到 ux 的值：
//	1111111111111111111111111111111111111111111111111111111111110110
// 如果是正数是原来的两倍，跟 ZigZag 是一样的，因为正数的最高位是 0
// 如果是负数还得 ux 取反，为 9 ，负数为奇数（绝对值的两倍-1），满足 ZigZag 的原理：
//	0000000000000000000000000000000000000000000000000000000000001001
//
//
// 问题就来了，为什么正数是对的，负数也是对的？
// 	正数上面解释过了，不管是将最高位移到最后一位还是左移一位都是扩大两倍，所以没问题
//	负数的话，要记住负数在计算机的编码方式，使用补码表示的，即补码=反码+1，
//	理解这两个为什么都可以就很容易了，其实不管是取反还是跟 v>>31 进行异或，
//	其实都是跟 1111111111111111111111111111111111 进行异或，效果跟取反是相同的。
//
// 	i <<= 1 & i >>= 1
//	i 为正，右移高位补 0 ，左移低位补 0
//	i 为负，右移高位补 1 ，左移低位补 0
//
//
func (p *Buffer) EncodeZigzag32(x uint64) error {
	// use signed number to get arithmetic right shift.
	return p.EncodeVarint(uint64((uint32(x) << 1) ^ uint32((int32(x) >> 31))))
}

// EncodeRawBytes writes a count-delimited byte buffer to the Buffer.
// This is the format used for the bytes protocol buffer type and for embedded messages.
func (p *Buffer) EncodeRawBytes(b []byte) error {
	p.EncodeVarint(uint64(len(b)))
	p.buf = append(p.buf, b...)
	return nil
}

// EncodeStringBytes writes an encoded string to the Buffer.
// This is the format used for the proto2 string type.
//
// 序列化字符串的时候，会先把字符串的长度通过编码 Varint 的方式，写到 buf 中，长度后面再紧跟着 string。
// 这也就是 tag - length - value 的实现
func (p *Buffer) EncodeStringBytes(s string) error {
	p.EncodeVarint(uint64(len(s)))
	p.buf = append(p.buf, s...)
	return nil
}

// Marshaler is the interface representing objects that can marshal themselves.
type Marshaler interface {
	Marshal() ([]byte, error)
}

// EncodeMessage writes the protocol buffer to the Buffer,
// prefixed by a varint-encoded length.
func (p *Buffer) EncodeMessage(pb Message) error {
	// 计算消息的真实大小
	siz := Size(pb)
	// 用 varint 编码 size 并存储到 p.buf 中
	p.EncodeVarint(uint64(siz))
	// 执行 pb 编码，将 msg 存储到 p.buf 中
	return p.Marshal(pb)
}

// All protocol buffer fields are nillable, but be careful.
func isNil(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}
	return false
}
