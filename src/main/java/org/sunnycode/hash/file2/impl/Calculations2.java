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
package org.sunnycode.hash.file2.impl;

import java.nio.ByteBuffer;

import org.sunnycode.hash.LongHashMethods;
import org.sunnycode.hash.impl.MurmurHash;

/**
 * Encapsulates calculations related to HashFiles.
 */
public class Calculations2 {
  /** Number of radix files */
  public static final int RADIX_FILE_COUNT_POWER_OF_2 = 8;

  /** Number of radix files */
  public static final int RADIX_FILE_COUNT = (1 << RADIX_FILE_COUNT_POWER_OF_2);

  /** our trusty hash function */
  private static final MurmurHash hash = new MurmurHash();

  /** computes the size of an entry in the bucket table */
  public static int getBucketTableEntrySize(boolean isLargeCapacity, boolean isLargeFile) {
    return (isLargeCapacity ? 8 : 4) + (isLargeFile ? 8 : 4);
  }

  /** computes the size of an entry in the hash table */
  public static int getHashTableEntrySize(boolean isLongHash, boolean isLargeFile) {
    return (isLongHash ? 8 : 4) + (isLargeFile ? 8 : 4);
  }

  /** computes the hash of a given key */
  public static long computeHash(byte[] key, boolean longHash, boolean isUuid) {
    if (isUuid) {
      return LongHashMethods.condenseBytesIntoLong(key);
    }

    return longHash ? hash.computeMurmurLongHash(key, 0L) : hash.computeMurmurIntHash(key, 0);
  }

  /**
   * Returns the power-of-two number of buckets recommended for the specified number of elements. If
   * the specified number of elements is zero or less, we use 8 as the bucket power (corresponding
   * to 256 buckets). Otherwise the value is ((log base 2 of the ceiling power of 2) - 6), which
   * corresponds to at most 64 items per bucket on average. This value is then truncated between the
   * maximum and minumum values of 28 and 8.
   */
  public static int getBucketPower(long expectedElements) {
    if (expectedElements <= 0) {
      return 8;
    }

    int powerOf2 = (64 - Long.numberOfLeadingZeros(expectedElements));
    long ceiling = 1L << powerOf2;

    if (expectedElements > ceiling) {
      powerOf2 += 1;
    }

    int recommended = powerOf2 - 6;

    return Math.min(28, Math.max(8, recommended));
  }

  /** returns the inner hash "slot" for a given hash value */
  public static int getInnerSlot(long hashValue, int buckets) {
    return (int) (hashValue & ((1L << buckets) - 1L));
  }

  /** returns the outer slot (by radix) corresponding to a given hash value */
  public static int getOuterSlot(long hashValue, int buckets) {
    return getRadix(hashValue, buckets) << (buckets - 8);
  }

  /** returns the appropriate radix file for a given hash value */
  public static int getRadix(long hashValue, int buckets) {
    return (int) (getInnerSlot(hashValue, buckets) >> (buckets - 8));
  }

  /**
   * Computes the bucket position offsets (position-based, not index).
   */
  public static ByteBuffer getBucketPositionTable(int alignment, long[] bucketOffsets,
      long[] bucketSizes, long dataSegmentEndPosition, boolean isLongHash, boolean isLargeFile,
      boolean isLargeCapacity) {
    int buckets = bucketOffsets.length;
    ByteBuffer slotTableBytes = ByteBuffer.allocate(buckets * (isLargeCapacity ? 16 : 8));

    int longPointerSize = getHashTableEntrySize(isLongHash, isLargeFile);

    for (int i = 0; i < bucketOffsets.length; i++) {
      long tableSize = bucketSizes[i];
      long tableOffset = bucketOffsets[i];

      long tablePos = dataSegmentEndPosition + (tableOffset * longPointerSize);

      if (isLargeCapacity) {
        slotTableBytes.putLong(tablePos >> alignment);
        slotTableBytes.putLong(tableSize);
      } else {
        slotTableBytes.putInt((int) (tablePos >> alignment));
        slotTableBytes.putInt((int) tableSize);
      }

    }

    slotTableBytes.rewind();

    return slotTableBytes;
  }

  /**
   * Computes the offsets (index, not byte position) of the buckets.
   */
  public static long[] computeBucketOffsets(long[] bucketCounts) {
    long[] bucketOffsets = new long[bucketCounts.length];

    int curEntry = 0;
    for (int i = 0; i < bucketCounts.length; i++) {
      bucketOffsets[i] = curEntry;
      curEntry += bucketCounts[i];
    }

    return bucketOffsets;
  }
}
