package com.stockpro.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class CacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Cacheable(value = "users", key = "#email")
    public Object getUserFromCache(String email) {
        log.debug("Cache miss for user: {}", email);
        return null;
    }

    public void putUserInCache(String email, Object user, long ttlMinutes) {
        log.debug("Putting user in cache: {}", email);
        redisTemplate.opsForValue().set("user:" + email, user, ttlMinutes, TimeUnit.MINUTES);
    }

    public Object getUserFromRedis(String email) {
        return redisTemplate.opsForValue().get("user:" + email);
    }

    @CacheEvict(value = "users", key = "#email")
    public void evictUserFromCache(String email) {
        log.debug("Evicting user from cache: {}", email);
        redisTemplate.delete("user:" + email);
    }

    public void putTokenInCache(String token, Object data, long ttlMinutes) {
        redisTemplate.opsForValue().set("token:" + token, data, ttlMinutes, TimeUnit.MINUTES);
    }

    public Object getTokenFromCache(String token) {
        return redisTemplate.opsForValue().get("token:" + token);
    }

    public void evictTokenFromCache(String token) {
        redisTemplate.delete("token:" + token);
    }

    public boolean isTokenBlacklisted(String token) {
        Boolean hasKey = redisTemplate.hasKey("blacklist:" + token);
        return hasKey != null && hasKey;
    }

    public void blacklistToken(String token, long ttlMinutes) {
        redisTemplate.opsForValue().set("blacklist:" + token, "blacklisted", ttlMinutes, TimeUnit.MINUTES);
    }
}