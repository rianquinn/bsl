template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
lower(const bsl::integer<T> &val, const unsigned &bits = BSL_PAGE_SHIFT) noexcept -> integer<T>
{
    return integer<T>{val.get() & ((static_cast<T>(1) << bits) - 1)};
}
