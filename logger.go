// Copyright (c) 2016, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

package main

import (
	"log"
	"os"
)

const capacity = 32768

type Logger struct {
	file string
	fp   *os.File
	done chan bool
}

func NewLogger(fileName string, done chan bool) (l *Logger) {
	if _, err := os.Stat(fileName); err == nil {
		_ = os.Rename(fileName, fileName+".old")
	}

	fp, err := os.Create(fileName)
	if err != nil {
		// We should stop here
		log.Fatal(err)
	}
	return &Logger{fileName, fp, done}
}

func (l *Logger) Process(record chan []byte) {
	defer l.fp.Close()
	for event := range record {
		_, err := l.fp.Write(event)
		if err != nil {
			log.Println(err)
		}
	}
	
	log.Println(l.file + ": exiting... log-done")
	l.done <- true
}
