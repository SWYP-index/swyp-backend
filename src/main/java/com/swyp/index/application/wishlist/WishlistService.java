package com.swyp.index.application.wishlist;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.user.User;
import com.swyp.index.domain.wishlist.Wishlist;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.infrastructure.repository.WishlistRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryDto;
import com.swyp.index.presentation.dto.wishlist.WishlistResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class WishlistService {

    private final WishlistRepository wishlistRepository;
    private final UserRepository userRepository;
    private final BookRepository bookRepository;

    public void addWish(Long userId, String isbn){
        User user = userRepository.findById(userId).orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        Book book = bookRepository.findByIsbn(isbn).orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));
        if (wishlistRepository.existsByUserAndBook(user, book)) {
            return;
        }
        wishlistRepository.save(new Wishlist(user, book));
    }

    public void removeWish(Long userId, String isbn){
        User user = userRepository.findById(userId).orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        Book book = bookRepository.findByIsbn(isbn).orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));
        Wishlist wish = wishlistRepository.findByUserAndBook(user, book)
                .orElseThrow(() -> new CustomException(ErrorCode.WISHLIST_ITEM_NOT_FOUND)); // 전용 에러코드 사용
        wishlistRepository.delete(wish);
    }

    @Transactional(readOnly = true)
    public List<WishlistResponseDto> getWishlist(Long userId){
        return wishlistRepository.findWishesByUserId(userId).stream()
                .map(wish -> WishlistResponseDto.from(wish.getBook()))
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public boolean checkWishStatus(Long userId, String isbn) {
        // 책이 DB에 없는 경우에도 false를 반환해야 하므로 orElse(false) 사용
        return bookRepository.findByIsbn(isbn)
                .map(book -> {
                    User user = userRepository.findById(userId).orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
                    return wishlistRepository.existsByUserAndBook(user, book);
                })
                .orElse(false);
    }
}
