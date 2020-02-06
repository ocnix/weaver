https://blog.golang.org/go-slices-usage-and-internals

Slices are passed by the following header:


type SliceHeader struct {
    Data uintptr
    Len  int
    Cap  int
}

## Int64 slice:

```
package main

//go:noinline
func test_function(a []int64) {}

func main() {
	test_function([]int64{1, 2, 3, 5})
}
```

```
SP+0:	149 (0x95)
SP+1:	35 (0x23)
SP+2:	69 (0x45)
SP+3:	0 (0x0)
SP+4:	0 (0x0)
SP+5:	0 (0x0)
SP+6:	0 (0x0)
SP+7:	0 (0x0)

SP+8:	48 (0x30)
SP+9:	199 (0xc7)
SP+10:	4 (0x4)
SP+11:	0 (0x0)
SP+12:	192 (0xc0)
SP+13:	0 (0x0)
SP+14:	0 (0x0)
SP+15:	0 (0x0)

SP+16:	4 (0x4)
SP+17:	0 (0x0)
SP+18:	0 (0x0)
SP+19:	0 (0x0)
SP+20:	0 (0x0)
SP+21:	0 (0x0)
SP+22:	0 (0x0)
SP+23:	0 (0x0)

SP+24:	4 (0x4)
SP+25:	0 (0x0)
SP+26:	0 (0x0)
SP+27:	0 (0x0)
SP+28:	0 (0x0)
SP+29:	0 (0x0)
SP+30:	0 (0x0)
SP+31:	0 (0x0)

SP+32:	1 (0x1)
SP+33:	0 (0x0)
SP+34:	0 (0x0)
SP+35:	0 (0x0)
SP+36:	0 (0x0)
SP+37:	0 (0x0)
SP+38:	0 (0x0)
SP+39:	0 (0x0)

SP+40:	2 (0x2)
SP+41:	0 (0x0)
SP+42:	0 (0x0)
SP+43:	0 (0x0)
SP+44:	0 (0x0)
SP+45:	0 (0x0)
SP+46:	0 (0x0)
SP+47:	0 (0x0)

SP+48:	3 (0x3)
SP+49:	0 (0x0)
SP+50:	0 (0x0)
SP+51:	0 (0x0)
SP+52:	0 (0x0)
SP+53:	0 (0x0)
SP+54:	0 (0x0)
SP+55:	0 (0x0)

SP+56:	5 (0x5)
SP+57:	0 (0x0)
SP+58:	0 (0x0)
SP+59:	0 (0x0)
SP+60:	0 (0x0)
SP+61:	0 (0x0)
SP+62:	0 (0x0)
SP+63:	0 (0x0)
```

## Int32 slice:

```
func test_function(a []int32) {}

func main() {
	test_function([]int32{1, 2, 3, 5})
}
```

```
SP+0:	137 (0x89)
SP+1:	35 (0x23)
SP+2:	69 (0x45)
SP+3:	0 (0x0)
SP+4:	0 (0x0)
SP+5:	0 (0x0)
SP+6:	0 (0x0)
SP+7:	0 (0x0)

SP+8:	64 (0x40)
SP+9:	199 (0xc7)
SP+10:	4 (0x4)
SP+11:	0 (0x0)
SP+12:	192 (0xc0)
SP+13:	0 (0x0)
SP+14:	0 (0x0)
SP+15:	0 (0x0)

SP+16:	4 (0x4)
SP+17:	0 (0x0)
SP+18:	0 (0x0)
SP+19:	0 (0x0)
SP+20:	0 (0x0)
SP+21:	0 (0x0)
SP+22:	0 (0x0)
SP+23:	0 (0x0)

SP+24:	4 (0x4)
SP+25:	0 (0x0)
SP+26:	0 (0x0)
SP+27:	0 (0x0)
SP+28:	0 (0x0)
SP+29:	0 (0x0)
SP+30:	0 (0x0)
SP+31:	0 (0x0)

SP+32:	1 (0x1)
SP+33:	0 (0x0)
SP+34:	0 (0x0)
SP+35:	0 (0x0)

SP+36:	2 (0x2)
SP+37:	0 (0x0)
SP+38:	0 (0x0)
SP+39:	0 (0x0)

SP+40:	3 (0x3)
SP+41:	0 (0x0)
SP+42:	0 (0x0)
SP+43:	0 (0x0)

SP+44:	5 (0x5)
SP+45:	0 (0x0)
SP+46:	0 (0x0)
SP+47:	0 (0x0)
```

## Bytes

```
package main

//go:noinline
func test_function(a []byte) {}

func main() {
	test_function([]byte{1, 2, 3, 5})
}
```

```
SP+0:	135 (0x87)
SP+1:	35 (0x23)
SP+2:	69 (0x45)
SP+3:	0 (0x0)
SP+4:	0 (0x0)
SP+5:	0 (0x0)
SP+6:	0 (0x0)
SP+7:	0 (0x0)

SP+8:	76 (0x4c)
SP+9:	199 (0xc7)
SP+10:	4 (0x4)
SP+11:	0 (0x0)
SP+12:	192 (0xc0)
SP+13:	0 (0x0)
SP+14:	0 (0x0)
SP+15:	0 (0x0)

SP+16:	4 (0x4)
SP+17:	0 (0x0)
SP+18:	0 (0x0)
SP+19:	0 (0x0)
SP+20:	0 (0x0)
SP+21:	0 (0x0)
SP+22:	0 (0x0)
SP+23:	0 (0x0)

SP+24:	4 (0x4)
SP+25:	0 (0x0)
SP+26:	0 (0x0)
SP+27:	0 (0x0)
SP+28:	0 (0x0)
SP+29:	0 (0x0)
SP+30:	0 (0x0)
SP+31:	0 (0x0)

SP+32:	24 (0x18)
SP+33:	161 (0xa1)
SP+34:	1 (0x1)
SP+35:	0 (0x0)

SP+36:	1 (0x1)

SP+37:	2 (0x2)

SP+38:	3 (0x3)

SP+39:	5 (0x5)
```

```
package main

//go:noinline
func test_function(a []byte) {}

func main() {
	test_function([]byte{5, 6, 7, 8, 9})
}
```

```
SP+0:	146 (0x92)
SP+1:	35 (0x23)
SP+2:	69 (0x45)
SP+3:	0 (0x0)
SP+4:	0 (0x0)
SP+5:	0 (0x0)
SP+6:	0 (0x0)
SP+7:	0 (0x0)

SP+8:	75 (0x4b)
SP+9:	199 (0xc7)
SP+10:	4 (0x4)
SP+11:	0 (0x0)
SP+12:	192 (0xc0)
SP+13:	0 (0x0)
SP+14:	0 (0x0)
SP+15:	0 (0x0)

SP+16:	5 (0x5)
SP+17:	0 (0x0)
SP+18:	0 (0x0)
SP+19:	0 (0x0)
SP+20:	0 (0x0)
SP+21:	0 (0x0)
SP+22:	0 (0x0)
SP+23:	0 (0x0)

SP+24:	5 (0x5)
SP+25:	0 (0x0)
SP+26:	0 (0x0)
SP+27:	0 (0x0)
SP+28:	0 (0x0)
SP+29:	0 (0x0)
SP+30:	0 (0x0)
SP+31:	0 (0x0)

SP+32:	24 (0x18)
SP+33:	161 (0xa1)
SP+34:	1 (0x1)

SP+35:	5 (0x5)
SP+36:	6 (0x6)
SP+37:	7 (0x7)
SP+38:	8 (0x8)
SP+39:	9 (0x9)

```