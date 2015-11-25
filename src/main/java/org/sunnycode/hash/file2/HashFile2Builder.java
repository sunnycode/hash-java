/**
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package org.sunnycode.hash.file2;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.sunnycode.hash.file2.impl.Calculations2;
import org.sunnycode.hash.file2.impl.FileOperations2;
import org.sunnycode.hash.file2.impl.Header2;

/**
 * Creates a HashFile, version 2. Inspired by DJB's CDB file format, we just introduce a different
 * hash function (murmur) and (up to) 64-bit hash cades and position offsets.
 */
public final class HashFile2Builder {
  /** size of write buffer for main data file */
  private static final int MAIN_WRITE_BUFFER_SIZE = 16 * 1024 * 1024; // 16MB

  /** size of write buffer for each of the radix files */
  private static final int HASH_WRITE_BUFFER_SIZE = 512 * 1024; // 512K

  /** path to the main data file */
  private final String dataFilePath;

  /** filename prefix for each of the radix files */
  private final String radixFilePrefix;

  /** The RandomAccessFile for the hash file contents */
  private final DataOutputStream dataFile;

  /** The RandomAccessFile for the hash file pointers */
  private final DataOutputStream[] hashCodeList;

  /** The number of entries in each bucket */
  private long[] bucketCounts = null;

  /** The position of the next key insertion in the file */
  private long dataFilePosition = -1;

  private final FileOperations2 fileOps;

  /**
   * Constructs a HashFileBuilder object and prepares it for the creation of a HashFile, version 2.
   */
  public HashFile2Builder(String filepath, long expectedElements) throws IOException {
    this(false, filepath, expectedElements, ByteSize.FOUR, ByteSize.FOUR, true, true, true, false,
        false);
  }

  /**
   * Constructs a HashFileBuilder object and prepares it for the creation of a HashFile, version 2.
   */
  public HashFile2Builder(boolean isAssociative, String filepath, long expectedElements,
      ByteSize keySize, ByteSize valueSize, boolean isLongHash, boolean isLargeCapacity,
      boolean isLargeFile, boolean isUuid, boolean isPrimitive) throws IOException {
    if (isAssociative && !isLongHash) {
      throw new IllegalArgumentException(
          "Associative HashFiles must use long hash to reduce collisions!");
    }

    if (isAssociative && !ByteSize.ZERO.equals(keySize)) {
      throw new IllegalArgumentException("Associative HashFiles must use key size zero!");
    }

    int bucketPower = Calculations2.getBucketPower(expectedElements);
    Header2 header =
        new Header2((byte) bucketPower, keySize, valueSize, isAssociative, isLongHash,
            isLargeCapacity, isLargeFile, isUuid, isPrimitive);

    this.fileOps = FileOperations2.fromHeader(header);
    this.bucketCounts = new long[header.getBuckets()];

    this.dataFilePath = filepath;
    this.radixFilePrefix = filepath + ".list.";

    this.dataFile =
        new DataOutputStream(new BufferedOutputStream(new FileOutputStream(filepath),
            MAIN_WRITE_BUFFER_SIZE));

    this.hashCodeList = new DataOutputStream[header.getRadixFileCount()];
    for (int i = 0; i < header.getRadixFileCount(); i++) {
      String filename = String.format("%s%02X", radixFilePrefix, i);
      File hashFile = new File(filename);
      hashCodeList[i] =
          new DataOutputStream(new BufferedOutputStream(new FileOutputStream(hashFile),
              HASH_WRITE_BUFFER_SIZE));
      hashFile.deleteOnExit();
    }

    this.dataFilePosition = header.getTotalHeaderLength();
    this.dataFile.write(new byte[(int) dataFilePosition]);
  }

  /**
   * Adds a new entry to the HashFile.
   * 
   * @param key The key to add to the database.
   * @param data The data associated with this key.
   * @exception java.io.IOException If an error occurs adding the key to the HashFile.
   */
  public synchronized void add(byte[] key, byte[] data) throws IOException {
    long oldPos = this.dataFilePosition;

    this.dataFilePosition =
        this.fileOps.writeKeyVaue(this.dataFile, this.dataFilePosition, key, data);

    this.fileOps.writeHashEntry(hashCodeList, bucketCounts, oldPos, key);
  }

  /**
   * Bulk-adds HashEntry instances from one hash file to another. In the future, this operation may
   * be optimized by concatenating data segments and hash table segments. (Hash codes stay the same,
   * offsets would just need to be incremented by the existing data size)
   * 
   * @param entries Iterable<HashEntry> entries to add
   * @exception java.io.IOException If an error occurs adding the entries to the HashFile.
   */
  public void addAll(Iterable<HashEntry> entries) throws IOException {
    for (HashEntry entry : entries) {
      add(entry.getKey(), entry.getValue());
    }
  }

  /**
   * Finishes building the HashFile.
   */
  public synchronized void finish() throws IOException {
    this.fileOps.finish(this.dataFilePosition, this.dataFilePath, this.dataFile,
        this.radixFilePrefix, this.hashCodeList, this.bucketCounts);
  }
}
