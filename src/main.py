import re


isALetterRegex = re.compile(r"[a-z]", re.IGNORECASE)
alphabetSize = 26

# matches words and contractions
extractWordsRegex = re.compile(r"\b((?<!')[\w-]+('\w*)?)|([\w-]+)\b", re.IGNORECASE)


def encrypt(plaintext: str, n: int):
    """
    shifts the letters to the right 'n' times
    """
    cipher = ""

    for char in plaintext:
        # check if the char is a letter
        if isALetterRegex.search(char) is not None:
            baseValue = ord('a')
            asciiValue = ord(char)

            # handle uppercase letters
            if asciiValue < baseValue:
                baseValue = ord('A')

            # shift the character by 'n' letters
            char = chr((asciiValue + n - baseValue) % alphabetSize + baseValue)

        cipher += char

    return cipher


def decrypt(cipher: str, n: int):
    """
    shifts the letters to the left 'n' times
    """
    plaintext = ""

    for char in cipher:
        # check if the char is a letter
        if isALetterRegex.search(char) is not None:
            baseValue = ord('a')
            asciiValue = ord(char)

            # handle uppercase letters
            if asciiValue < baseValue:
                baseValue = ord('A')

            # shift the character by 'n' letters
            char = chr((asciiValue - n - baseValue) % alphabetSize + baseValue)

        plaintext += char

    return plaintext


def bruteForceAnyOccurrence(cipher: str, vocabulary: str):
    """
    brute force by checking if any encrypted vocab word appears *anywhere* in the ciphertext

    *anywhere* meaning the word can be a substring of another larger word which may be unwanted
    """

    # make a set of words out of the vocab
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    vocabularySet = set(vocabulary.lower().split())

    # loop through all the possible cipher keys
    # it starts at zero bc the ciphertext could already be the plaintext
    for n in range(alphabetSize):
        # make a set of cipher words out of the vocab
        encryptedVocabulary = [encrypt(vocabWord, n) for vocabWord in vocabularySet]

        # check if any cipher vocab word appears *anywhere* in the ciphertext
        # *anywhere* meaning the word can be a substring of another larger word which may be unwanted
        for vocabWord in encryptedVocabulary:
            if cipher.find(vocabWord) != -1:
                plaintext = decrypt(cipher, n)
                return plaintext, n

    # return None if the plaintext could not be found with the provided vocabulary
    return None


def bruteForceMatchingToCiphertext(cipher: str, vocabulary: str):
    """
    brute force by matching encrypted vocab words to the ciphertext

    falls back on to matching any subtring occurrence of the cipher vocab words
    """

    # make a set of words out of the vocab
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    words = extractWordsRegex.findall(vocabulary)
    words = set([word[0].lower() for word in words])
    words = [re.escape(word) for word in words]

    # loop through all the possible cipher keys
    # it starts at zero bc the ciphertext could already be the plaintext
    for n in range(alphabetSize):
        # escape regex special chars and ecrypt the words from the set
        encryptedVocabulary = [encrypt(vocabWord, n) for vocabWord in words]

        # check if any cipher vocab word matches the ciphertext
        for vocabWord in encryptedVocabulary:
            if re.search("(\\b" + vocabWord + "\\b)", cipher, re.IGNORECASE) is not None:
                plaintext = decrypt(cipher, n)
                return plaintext, n

    # look for any occurrence as a fallback
    return bruteForceAnyOccurrence(cipher, vocabulary)


def bruteForce(cipher: str, vocabulary: str):
    """
    brute force by matching all cipher words to the vocab words

    falls back on to matching any subtring occurrence of the cipher vocab words
    """

    cipherWords = cipher.split()

    # make a set of words out of the vocab
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    vocabWords = extractWordsRegex.findall(vocabulary)
    vocabWords = set([word[0].lower() for word in vocabWords])
    vocabWords = [re.escape(word) for word in vocabWords]

    # loop through all the possible cipher keys
    # it starts at zero bc the ciphertext could already be the plaintext
    for n in range(alphabetSize):
        # escape regex special chars and ecrypt the words from the set
        encryptedVocabulary = set([encrypt(vocabWord, n) for vocabWord in vocabWords])

        foundKey = True

        # check if the cipher words are in the encrypted vocab words
        for cipherWord in cipherWords:
            if not cipherWord in encryptedVocabulary:
                foundKey = False
                break

        if foundKey:
            plaintext = decrypt(cipher, n)
            return plaintext, n

    # look for encrypted vocab words in the ciphertext as a fallback
    return bruteForceMatchingToCiphertext(cipher, vocabulary)
