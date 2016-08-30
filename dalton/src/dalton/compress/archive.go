package compress

import (
	"archive/tar"
	"io"
	"fmt"
	"os"
	"path/filepath"
)


type TarFile struct {
	Name string
	Contents []byte
	Ext string
}

func NewArchiver(algo string , WriteTo io.WriteCloser) *tar.Writer {

	//writer := getWriterWith(algo,WriteTo)
	//now create the tar Archiver
	tarArchiver := tar.NewWriter(WriteTo)
	return tarArchiver
}
func AddFile(archiver *tar.Writer , path string) error {

	if len(path) <=0 {
		return fmt.Errorf("Path should not be null or empty")
	}
	if archiver == nil {
		return fmt.Errorf("The Archiver should not be null")
	}
	//read the path
	file , err := os.OpenFile(path,os.O_RDONLY,0644)
	if err != nil {
		return err
	}
	defer file.Close()
	stat , err := file.Stat()
	if err != nil {
		return err
	}
	header := &tar.Header{
		Size:stat.Size(),
		Mode:int64(stat.Mode().Perm()),
		Name:stat.Name(),
		ModTime:stat.ModTime(),
	}
	//now write the header into the archiver
	if err := archiver.WriteHeader(header); err != nil{
		return err
	}
	//now copy the contents of the file into the archiver header
	n , err := io.Copy(archiver,file)
	if err != nil {
		return err
	}
	if n < stat.Size() {
		return fmt.Errorf("Unable to copy the entire file into the Archiver")
	}
	//If everything went fine, just return nothing
	return nil
}
func ExtractTarFrom(src io.Reader) ([]TarFile , error) {
	var tarFiles []TarFile
	reader := tar.NewReader(src)

	for{
		hdr , err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil , fmt.Errorf("Failed to read the next Entry in the Tar File %s",err)
		}
		//read the contents of the current header
		contents := make([]byte,hdr.Size)
		n , err := io.ReadFull(reader,contents)
		if int64(n) < hdr.Size{
			return nil , fmt.Errorf("Failed to read The Full Bytes for the current entry in the Tar file %s",err)
		}
		tarFile := &TarFile{
			 Name:hdr.Name,
			Contents:contents,
			Ext:filepath.Ext(hdr.Name),
		}

		//now append it into the rar files
		tarFiles = append(tarFiles,*tarFile)
	}
	//Finally , return the correct tar files
	return tarFiles,nil


}


