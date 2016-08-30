package compress

import (
	"bytes"
	"compress/gzip"
	"compress/flate"
	"compress/lzw"
	"compress/zlib"
	"fmt"
	"io"
	"io/ioutil"
)


const (
	COMPRESS_GZIP_ALGORITHM = "gzip"
	COMPRESS_FLATE_ALGORITHM = "flate"
	COMPRESS_LZW_ALGORITHM ="lzw"
	COMPRESS_ZLIB_ALGORITHM="zlib"
)
type CompressDecompress interface {

	Compress(algo  string , data []byte) []byte
	Decompress(algo string , compressed []byte) []byte
}
/*
   This function will compress the uncompressed Data int Compressed Data

 */
func Compress(algo string , data []byte) []byte{


	writer , buffer := getWriter(algo)
	writer.Write(data)
	writer.Close() // close the writer
	//now return the compressed data
	return buffer.Bytes()
}
/*
    This function will decompress data back into their original format
 */



func Decompress(algo string , data []byte) []byte {

	compressedData := bytes.NewReader(data)
	//compressedData.Read(data)
	reader := getReader(algo,compressedData)
	defer reader.Close()
	//reader.Read(data)
	//now read all the bytes
	outputData , err := ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	return outputData
}
func getReader(algo string , b io.Reader) (io.ReadCloser){

	switch(algo){
	case COMPRESS_FLATE_ALGORITHM:
		compressReader := flate.NewReader(b)
		return compressReader
	case COMPRESS_GZIP_ALGORITHM:
		compressReader , err := gzip.NewReader(b)
		if err != nil {
			panic(fmt.Errorf("Failed to Create the Decompressor : %q",err))
		}
		return compressReader
	case COMPRESS_LZW_ALGORITHM:
		compressReader := lzw.NewReader(b,lzw.MSB,8)
		return compressReader
	case COMPRESS_ZLIB_ALGORITHM:
		compressReader , err := zlib.NewReader(b)
		if err != nil {
			panic(err)
		}
		return compressReader
	}
	return nil
}


func getWriterWith(algo string, writerDst io.Writer) io.WriteCloser {

	switch(algo) {
	case COMPRESS_ZLIB_ALGORITHM:
		compressWriter := zlib.NewWriter(writerDst)
		return compressWriter
	case COMPRESS_LZW_ALGORITHM:
		compressWriter := lzw.NewWriter(writerDst,lzw.MSB,8)
		return compressWriter
	case COMPRESS_GZIP_ALGORITHM:
		compressWriter := gzip.NewWriter(writerDst)
		return compressWriter
	case COMPRESS_FLATE_ALGORITHM:
		compressWriter , err := flate.NewWriter(writerDst,flate.BestCompression)
		if err != nil {
			panic(err)
		}
		return compressWriter
	}
	return nil
}

func getWriter(algo string) (io.WriteCloser,*bytes.Buffer) {

	var b bytes.Buffer

	switch(algo) {
	case COMPRESS_ZLIB_ALGORITHM:
		compressWriter := zlib.NewWriter(&b)
		return compressWriter , &b
	case COMPRESS_LZW_ALGORITHM:
		compressWriter := lzw.NewWriter(&b,lzw.MSB,8)
		return compressWriter, &b
	case COMPRESS_GZIP_ALGORITHM:
		compressWriter := gzip.NewWriter(&b)
		return compressWriter , &b
	case COMPRESS_FLATE_ALGORITHM:
		compressWriter , err := flate.NewWriter(&b,flate.BestCompression)
		if err != nil {
			panic(err)
		}
		return compressWriter , &b
	}
	return nil,nil
}