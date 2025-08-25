package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.user.User;
import com.swyp.index.domain.wishlist.Wishlist;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface WishlistRepository extends CrudRepository<Wishlist, Long> {
    Optional<Wishlist> findByUserAndBook(User user, Book book);
    boolean existsByUserAndBook(User user, Book book);

    @Query("SELECT wl FROM Wishlist wl JOIN FETCH wl.book WHERE wl.user.id = :userId ORDER BY wl.id DESC")
    List<Wishlist> findWishesByUserId(@Param("userId") Long userId);
}
