import strconv

fn hex_to_bytes(data string) []byte {
	mut nums := []byte{}
	for i := 0; i < data.len; i += 2 {
		end := if i + 2 > data.len { data.len } else { i + 2 }
		num := strconv.parse_uint(data[i..end], 16, 8)
		nums << byte(num)
	}
	return nums
}

fn hex_to_32(mut res [32]byte, data string) {
	for i := 0; i < 32; i++ {
		num := strconv.parse_uint(data[(i * 2)..(i * 2 + 2)], 16, 8)
		res[i / 2] = byte(num)
	}
}

fn bytes_to_32(mut res [32]byte, data []byte) {
	for i := 0; i < 32; i++ {
		res[i] = data[i]
	}
}
