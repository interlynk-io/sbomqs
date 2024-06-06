package engine

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestRetrieveFilesX(t *testing.T) {
	// Create test directories
	err := os.MkdirAll("testDir", os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	err = os.WriteFile("testDir/testFile.txt", []byte("test content file1"), os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	err = os.MkdirAll("testDir1", os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}

	err = os.WriteFile("testDir1/testFile1.txt", []byte("test content in testDir1/testFile1.txt"), os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	err = os.MkdirAll("testDir2", os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}

	err = os.WriteFile("testDir2/testFile2.txt", []byte("test content"), os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}

	// Test with a single file
	ctx := context.Background()
	files, paths, err := retrieveFiles(ctx, []string{"testDir/testFile.txt"})
	if err != nil {
		t.Errorf("Error retrieving files: %s", err)
	}
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}
	if len(paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(paths))
	}
	if files[0] != "testDir/testFile.txt" {
		t.Errorf("Expected file path to be 'testDir/testFile.txt', got '%s'", files[0])
	}

	// Test with multiple files
	files, paths, err = retrieveFiles(ctx, []string{"testDir1/testFile1.txt", "testDir2/testFile2.txt"})
	if err != nil {
		t.Errorf("Error retrieving files: %s", err)
	}
	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(files))
	}
	if len(paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(paths))
	}
	if files[0] != "testDir1/testFile1.txt" {
		t.Errorf("Expected file path to be 'testDir1/testFile1.txt', got '%s'", files[0])
	}
	if files[1] != "testDir2/testFile2.txt" {
		t.Errorf("Expected file path to be 'testDir2/testFile2.txt', got '%s'", files[1])
	}

	// Test with an error
	files, paths, err = retrieveFiles(ctx, []string{"nonExistentDir"})
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if len(files) != 0 {
		t.Errorf("Expected 0 files, got %d", len(files))
	}
	if len(paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(paths))
	}
	if paths[0] != "nonExistentDir" {
		t.Errorf("Expected path to be 'nonExistentDir', got '%s'", paths[0])
	}
}
