#pragma once

#define BIONIC_DISALLOW_COPY_AND_ASSIGN(T) T(const T&) = delete; T& operator=(const T&) = delete
#define BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS(T) T() = delete; BIONIC_DISALLOW_COPY_AND_ASSIGN(T)
#define __BIONIC_ALIGN(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))
