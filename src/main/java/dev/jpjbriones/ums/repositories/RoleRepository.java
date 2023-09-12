package dev.jpjbriones.ums.repositories;

import dev.jpjbriones.ums.models.ERole;
import dev.jpjbriones.ums.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}